// 运行时镜像导出 + 反调试绕过（Frida）
// 用法：frida -l this.js -f <target.exe>  或  frida -l this.js <pid>
'use strict';

const MODULE_BASE = ptr('0x0000000000400000');
const IMAGE_SIZE = 24576;
const OUT_DIR = './dump';
const log = (m) => console.log('[+] ' + m);

function ensureDir() {
  try { new File(OUT_DIR + '/.keep', 'wb').write(''); } catch (e) {}
}

function writeFile(path, bytes) {
  const f = new File(path, 'wb');
  f.write(bytes);
  f.flush();
  f.close();
  log('wrote ' + path + ' (' + bytes.byteLength + ' bytes)');
}

// 取 PEB 指针（BeingDebugged / NtGlobalFlag 修补用）
function pebPointer() {
  try {
    const ntdll = Process.findModuleByName('ntdll.dll');
    if (!ntdll) return null;
    const addr = ntdll.findExportByName('NtCurrentTeb');
    if (addr === null) return null;
    const fn = new NativeFunction(addr, 'pointer', []);
    const teb = fn();
    return teb.add(Process.pointerSize === 8 ? 0x60 : 0x30).readPointer();
  } catch (e) { return null; }
}

function patchPeb() {
  const peb = pebPointer();
  if (peb === null) { log('PEB 指针不可得，跳过 PEB 修补（改用 API hook）'); return; }
  try {
    log('PEB @ ' + peb);
    peb.add(0x02).writeU8(0);            // BeingDebugged
    if (Process.pointerSize === 8) peb.add(0xBC).writeU32(0); // NtGlobalFlag (x64)
    else peb.add(0x68).writeU32(0);      // NtGlobalFlag (x86)
    const heap = peb.add(Process.pointerSize === 8 ? 0x30 : 0x18).readPointer();
    if (!heap.isNull()) {
      heap.add(Process.pointerSize === 8 ? 0x70 : 0x0C).writeU32(2); // Flags: 去掉 debug heap
    }
    log('PEB 已修补（BeingDebugged/NtGlobalFlag/Heap.Flags）');
  } catch (e) { log('PEB 修补失败: ' + e.message); }
}

// 模块镜像 dump（按 SizeOfImage 逐区读取，保留原始布局）
function dumpModule(tag) {
  ensureDir();
  const path = OUT_DIR + '/dump_' + (tag || 'image') + '_' + MODULE_BASE.toString(16) + '.bin';
  const total = IMAGE_SIZE;
  const buf = Memory.alloc(total);
  let copied = 0;
  Process.enumerateRanges('r--').forEach((range) => {
    const start = range.base;
    const end = range.base.add(range.size);
    const modEnd = MODULE_BASE.add(total);
    if (end.compare(MODULE_BASE) <= 0 || start.compare(modEnd) >= 0) return;
    const from = start.compare(MODULE_BASE) < 0 ? MODULE_BASE : start;
    const to = end.compare(modEnd) > 0 ? modEnd : end;
    const len = to.sub(from).toInt32();
    try {
      Memory.copy(buf.add(from.sub(MODULE_BASE).toInt32()), from, len);
      copied += len;
    } catch (e) { log('range 读取失败 ' + from + ': ' + e.message); }
  });
  writeFile(path, buf.readByteArray(total));
  log('dump 覆盖 ' + copied + '/' + total + ' 字节');
}

// 反调试 API 覆盖
const API_LIST = ["IsDebuggerPresent","VirtualProtect","GetTickCount"];
function hookApi(name) {
  let addr = null;
  ['kernel32.dll', 'kernelbase.dll', 'ntdll.dll'].forEach((mod) => {
    if (addr !== null) return;
    const m = Process.findModuleByName(mod);
    if (!m) return;
    addr = m.findExportByName(name);
  });
  if (addr === null) return;
  Interceptor.attach(addr, {
    onEnter(args) { this.name = name; },
    onLeave(retval) {
      const lower = this.name.toLowerCase();
      if (lower === 'isdebuggerpresent') { retval.replace(0); }
      else if (lower === 'checkremotedebuggerpresent') { retval.replace(1); }
      else if (lower.indexOf('ntqueryinformationprocess') >= 0) { retval.replace(0); }
      else if (lower === 'outputdebugstringa' || lower === 'outputdebugstringw') { retval.replace(0); }
      else if (lower.indexOf('gettickcount') === 0 || lower === 'queryperformancecounter') { retval.replace(1); }
      log('hit ' + this.name + ' -> ' + retval);
    }
  });
  log('hooked ' + name + ' @ ' + addr);
}

// RWX 转换监听：解压完成的直接信号，同时落盘当时的镜像
function watchProtect() {
  const names = ['VirtualProtect', 'NtProtectVirtualMemory', 'VirtualAlloc', 'NtAllocateVirtualMemory'];
  names.forEach((name) => {
    let addr = null;
    ['kernel32.dll', 'kernelbase.dll', 'ntdll.dll'].forEach((mod) => {
      if (addr !== null) return;
      const m = Process.findModuleByName(mod);
      if (m) addr = m.findExportByName(name);
    });
    if (addr === null) return;
    Interceptor.attach(addr, {
      onEnter(args) {
        const protect = name.indexOf('Protect') >= 0 ? args[2].toInt32() : args[2].toInt32();
        const isRwx = (protect & 0x40) !== 0 || (protect & 0x80) !== 0;
        if (!isRwx) return;
        log(name + ' rwx pending @ ' + args[0]);
        setTimeout(() => { try { dumpModule('rwx'); } catch (e) { log('rwx dump 失败: ' + e.message); } }, 0);
      }
    });
  });
}

// OEP 命中即 dump（静态候选地址）
function watchOep() {
  try {
    Interceptor.attach(ptr('0x0000000000401000'), { onEnter() { log('OEP hit'); dumpModule('oep'); } });
    log('OEP watch @ 0x0000000000401000');
  } catch (e) { log('OEP watch 失败: ' + e.message); }
}

setImmediate(() => {
  log('module base ' + MODULE_BASE + ' size ' + IMAGE_SIZE);
  patchPeb();
  API_LIST.forEach(hookApi);
  watchProtect();
  watchOep();
});

