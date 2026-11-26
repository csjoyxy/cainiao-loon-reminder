const assert = require("assert");
const crypto = require("crypto");
const lib = require("../scripts/cainiao_pickup.js");

function nodeMd5(s) {
  return crypto.createHash("md5").update(Buffer.from(s, "utf8")).digest("hex");
}

async function runTests() {
  // 1. MD5 一致性测试（含短串、跨 64 字节分块长串、中文与 Emoji）
  const samples = [
    "",
    "a",
    "abc",
    "message digest",
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef_extra",
    "token123&1732600000000&12574478&{\"pageSize\":50,\"currentPage\":1,\"needTemporality\":false,\"needDynInfo\":\"{'needFindTemporality':true,'needAppointment':true}\"}",
    "菜鸟驿站·万科城店 📦 取件码 3-2-1048",
  ];
  for (const s of samples) {
    assert.strictEqual(lib.md5(s), nodeMd5(s), `MD5 mismatch on: ${s}`);
  }
  console.log("✓ MD5 (ASCII + UTF-8 + multi-block) passed");

  // 2. 存储加密隔离测试（CTR + 模拟 Loon $crypto.aes GCM）
  const secretJson = JSON.stringify({ unb: "2200123456", cookie2: "sec_ck2", _m_h5_tk: "tok_123" });
  const encCtr = lib.encryptText(secretJson, "my-pin-888");
  assert(encCtr.startsWith("ctr1:"));
  assert(!encCtr.includes("sec_ck2"));
  assert.strictEqual(lib.decryptText(encCtr, "my-pin-888"), secretJson);
  assert.strictEqual(lib.decryptText(encCtr, "wrong-pin"), "");
  assert.strictEqual(lib.decryptText(encCtr.slice(0, -2) + "ff", "my-pin-888"), "");

  global.$crypto = {
    aes: {
      encrypt(plainBytes, opts) {
        const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(opts.key), Buffer.from(opts.iv));
        const ct = Buffer.concat([cipher.update(Buffer.from(plainBytes)), cipher.final()]);
        const tag = cipher.getAuthTag();
        return { ciphertext: new Uint8Array(ct), tag: new Uint8Array(tag) };
      },
      decrypt(cipherBytes, opts) {
        const decipher = crypto.createDecipheriv("aes-256-gcm", Buffer.from(opts.key), Buffer.from(opts.iv));
        decipher.setAuthTag(Buffer.from(opts.tag));
        const pt = Buffer.concat([decipher.update(Buffer.from(cipherBytes)), decipher.final()]);
        return new Uint8Array(pt);
      },
    },
  };
  const encGcm = lib.encryptText(secretJson, "gcm-pin");
  assert(encGcm.startsWith("gcm1:"));
  assert(!encGcm.includes("sec_ck2"));
  assert.strictEqual(lib.decryptText(encGcm, "gcm-pin"), secretJson);
  assert.strictEqual(lib.decryptText(encGcm, "other-pin"), "");
  delete global.$crypto;
  console.log("✓ Encrypted vault storage (CTR + AES-256-GCM) passed");

  // 3. iOS NSHTTPURLResponse 多条 Set-Cookie 逗号合并切分测试
  const combinedSetCookie =
    "_m_h5_tk=deadbeef999_1764140000000; Max-Age=604800; Expires=Thu, 03-Dec-2026 02:30:00 GMT; Domain=.taobao.com; Path=/; Secure, _m_h5_tk_enc=enc987654321; Max-Age=604800; Expires=Thu, 03-Dec-2026 02:30:00 GMT; Domain=.taobao.com; Path=/; Secure";
  const jar = { unb: "10086", cookie2: "ck2" };
  const changed = lib.absorbSetCookiesFromHeaders({ "Set-Cookie": combinedSetCookie }, jar);
  assert.strictEqual(changed, true);
  assert.strictEqual(jar._m_h5_tk, "deadbeef999_1764140000000");
  assert.strictEqual(jar._m_h5_tk_enc, "enc987654321");
  console.log("✓ Set-Cookie multi-header comma splitting passed");

  // 4. 捕获请求与端到端 MTOP 令牌续期 + 包裹通知流程测试
  const store = {};
  const notifications = [];
  global.$persistentStore = {
    read: (k) => store[k] || "",
    write: (v, k) => {
      if (v === undefined || v === null) delete store[k];
      else store[k] = String(v);
      return true;
    },
  };
  global.$notification = {
    post: (title, subtitle, content, attach) => {
      notifications.push({ title, subtitle, content, attach });
    },
  };

  const cfg = lib.parseConfig({
    capture_cookie: true,
    notify_empty: false,
    open_target: "cainiao://desktop/station_code",
    vault_pin: "unit-test-pin",
    manual_cookie: "",
  });

  // 4a. 匿名请求不应误存
  global.$request = {
    url: "https://h5.m.taobao.com/",
    headers: { Cookie: "cna=xyz; cookie2=anon123" },
  };
  lib.handleCaptureRequest(cfg, () => {});
  assert.strictEqual(notifications.length, 0);

  // 4b. 登录后请求应加密保存并弹 1 次通知（连续第二次同账号不刷屏）
  global.$request = {
    url: "https://h5api.m.taobao.com/h5/mtop.user.getusersimple/1.0/",
    headers: { Cookie: "unb=22099887766; cookie2=real_ck2; sgcookie=E100abc; tracknick=joy_user" },
  };
  lib.handleCaptureRequest(cfg, () => {});
  lib.handleCaptureRequest(cfg, () => {});
  assert.strictEqual(notifications.length, 1);
  assert(notifications[0].title.includes("捕获成功"));
  delete global.$request;

  // 4c. 模拟首次无 _m_h5_tk -> 返回 FAIL_SYS_TOKEN_EMPTY 下发新 token -> 第二次验签成功并返回包裹
  notifications.length = 0;
  let httpCalls = 0;
  global.$httpClient = {
    get(opts, cb) {
      httpCalls++;
      assert.strictEqual(opts.node, "DIRECT");
      const u = new URL(opts.url);
      const t = u.searchParams.get("t");
      const sign = u.searchParams.get("sign");
      const dataParam = u.searchParams.get("data");

      if (httpCalls === 1) {
        cb(
          null,
          {
            status: 200,
            headers: {
              "set-cookie":
                "_m_h5_tk=freshTokenAbc_1764150000000; Expires=Thu, 03-Dec-2026 10:00:00 GMT; Path=/, _m_h5_tk_enc=freshEncXyz; Path=/",
            },
          },
          JSON.stringify({ ret: ["FAIL_SYS_TOKEN_EMPTY::令牌为空"] })
        );
        return;
      }

      const expectedSign = nodeMd5(`freshTokenAbc&${t}&12574478&${dataParam}`);
      assert.strictEqual(sign, expectedSign, "MTOP retry signature mismatch");
      assert(opts.headers.Cookie.includes("_m_h5_tk=freshTokenAbc_1764150000000"));
      assert(opts.headers.Cookie.includes("_m_h5_tk_enc=freshEncXyz"));

      cb(
        null,
        { status: 200, headers: {} },
        JSON.stringify({
          ret: ["SUCCESS::调用成功"],
          data: {
            totalPage: 1,
            packages: [
              {
                mailNo: "YT1000001",
                partnerName: "圆通速递",
                logisticsStatus: "AGENT_SIGN",
                logisticsStatusDesc: "待取件",
                feature: { recommendPackageTitle: "无线蓝牙降噪耳机保护壳" },
                packageStation: {
                  stationId: "ST01",
                  stationName: "菜鸟驿站·阳光花园3栋店",
                  authCode: "3-2-1048",
                },
              },
              {
                mailNo: "ZT1000002",
                partnerName: "中通快递",
                logisticsStatus: "AGENT_SIGN",
                logisticsStatusDesc: "驿站代收",
                feature: { recommendPackageTitle: "浓缩咖啡豆500g" },
                packageStation: {
                  stationId: "ST01",
                  stationName: "菜鸟驿站·阳光花园3栋店",
                  authCode: "8-1-5520",
                },
              },
              {
                mailNo: "SF1000003",
                partnerName: "顺丰速运",
                logisticsStatus: "TRANSPORT",
                logisticsStatusDesc: "运输中",
                feature: { recommendPackageTitle: "机械键盘轴体" },
              },
              {
                mailNo: "JD1000004",
                partnerName: "京东快递",
                logisticsStatus: "SIGN",
                logisticsStatusDesc: "已签收",
                packageStation: {
                  stationId: "ST01",
                  stationName: "菜鸟驿站·阳光花园3栋店",
                  authCode: "1-1-0001",
                },
              },
            ],
          },
        })
      );
    },
  };

  await new Promise((resolve) => lib.runDailyCheck(cfg, resolve));
  assert.strictEqual(httpCalls, 2);
  assert.strictEqual(notifications.length, 1);
  assert.strictEqual(notifications[0].title, "📦 你有 2 个快递待取");
  assert(notifications[0].subtitle.includes("菜鸟驿站·阳光花园3栋店"));
  assert(notifications[0].subtitle.includes("另有 1 件在途"));
  assert(notifications[0].content.includes("【3-2-1048】圆通速递"));
  assert(notifications[0].content.includes("【8-1-5520】中通快递"));
  assert(!notifications[0].content.includes("1-1-0001"));
  assert.strictEqual(notifications[0].attach.clipboard, "3-2-1048 8-1-5520");
  assert.strictEqual(notifications[0].attach.openUrl, "cainiao://desktop/station_code");
  console.log("✓ End-to-end MTOP token refresh + pending parcel notification passed");

  // 5. 测试无待取件时：定时任务静默 vs 手动触发提示
  notifications.length = 0;
  global.$httpClient.get = (opts, cb) => {
    cb(
      null,
      { status: 200, headers: {} },
      JSON.stringify({
        ret: ["SUCCESS::调用成功"],
        data: {
          totalPage: 1,
          packages: [
            {
              mailNo: "SF1000003",
              partnerName: "顺丰速运",
              logisticsStatus: "TRANSPORT",
              logisticsStatusDesc: "运输中",
            },
          ],
        },
      })
    );
  };

  global.$script = { name: "菜鸟驿站每日待取检测" };
  await new Promise((resolve) => lib.runDailyCheck(cfg, resolve));
  assert.strictEqual(notifications.length, 0, "Cron should stay silent when 0 pending parcels");

  global.$script = { name: "立即检测一次待取快递" };
  await new Promise((resolve) => lib.runDailyCheck(cfg, resolve));
  assert.strictEqual(notifications.length, 1, "Manual generic run should notify even when 0 pending");
  assert(notifications[0].title.includes("今日暂无待取快递"));
  console.log("✓ Silent cron vs verbose manual trigger behavior passed");

  console.log("\nALL TESTS PASSED!");
}

runTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
