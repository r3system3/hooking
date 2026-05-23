// HOOKING - Scanner MCSettingsEvents / MCProfile / Jailbreak

const SUSPICIOUS_PROFILE_WORDS = [
  "aimbot",
  "freefire",
  "hack",
  "cheat",
  "inject",
  "injected",
  "hook",
  "frida",
  "dopamine",
  "ellekit",
  "trollstore",
  "cydia",
  "sileo",
  "substrate",
  "substitute",
  "libhooker",
  "apple-dns",
  "dns",
  "vpn",
  "proxy",
  "warp",
  "managed",
  "configuration"
]

const JAILBREAK_WORDS = [
  "frida",
  "frida-server",
  "re.frida.server",
  "dopamine",
  "ellekit",
  "/var/jb",
  "mobilesubstrate",
  "substrate",
  "cydiasubstrate",
  "substitute",
  "libsubstitute",
  "libhooker",
  "cydia",
  "sileo",
  "zebra",
  "trollstore",
  "debugserver",
  "ptrace",
  "lldb"
]

const TEXT_EXTENSIONS = [
  ".txt", ".log", ".ips", ".plist", ".mobileconfig",
  ".json", ".xml", ".trace", ".crash", ".analytics"
]

async function alertMsg(title, message) {
  let a = new Alert()
  a.title = title
  a.message = message
  a.addAction("OK")
  await a.present()
}

function isTextFile(path) {
  let p = path.toLowerCase()
  return TEXT_EXTENSIONS.some(ext => p.endsWith(ext))
}

function readTextSafe(fm, path) {
  try {
    return fm.readString(path)
  } catch (e) {
    return ""
  }
}

function walkDirectory(fm, dir, files = []) {
  let items = fm.listContents(dir)

  for (let item of items) {
    let path = fm.joinPath(dir, item)

    if (fm.isDirectory(path)) {
      walkDirectory(fm, path, files)
    } else if (isTextFile(path)) {
      files.push(path)
    }
  }

  return files
}

function getAllMatches(content, regex) {
  let out = []
  let m
  while ((m = regex.exec(content)) !== null) {
    out.push(m[1])
  }
  return out
}

function normalizeCode(code) {
  return String(code || "")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .trim()
}

function detectActionNear(content, index) {
  let start = Math.max(0, index - 600)
  let end = Math.min(content.length, index + 600)
  let block = content.slice(start, end).toLowerCase()

  if (
    block.includes("removal") ||
    block.includes("removed") ||
    block.includes("remove") ||
    block.includes("remoção") ||
    block.includes("remocao")
  ) {
    return "Remoção"
  }

  if (
    block.includes("install") ||
    block.includes("installed") ||
    block.includes("instalação") ||
    block.includes("instalacao")
  ) {
    return "Instalação"
  }

  return "Evento"
}

function detectDateNear(content, index) {
  let start = Math.max(0, index - 800)
  let end = Math.min(content.length, index + 800)
  let block = content.slice(start, end)

  let patterns = [
    /\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/,
    /\d{2}\/\d{2}\/\d{4}[, ]+\d{2}:\d{2}:\d{2}/,
    /\d{2}-\d{2}-\d{4}[, ]+\d{2}:\d{2}:\d{2}/,
    /\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/
  ]

  for (let r of patterns) {
    let m = block.match(r)
    if (m) return m[0]
  }

  return "Data não encontrada"
}

function isSuspiciousProfile(code) {
  let lower = code.toLowerCase()
  return SUSPICIOUS_PROFILE_WORDS.some(w => lower.includes(w.toLowerCase()))
}

function extractMCSettingsProfiles(content, file) {
  let events = []
  let regexes = [
    /<key>([^<]{8,200})<\/key>\s*<dict>/gi,
    /<string>([^<]{8,200})<\/string>/gi,
    /([a-f0-9]{32,80})/gi,
    /((?:com\.)[a-zA-Z0-9._~\-]{5,120})/g
  ]

  for (let regex of regexes) {
    let m
    while ((m = regex.exec(content)) !== null) {
      let code = normalizeCode(m[1])

      if (!code) continue
      if (code.length < 8) continue
      if (code.includes("http")) continue
      if (code.includes("plist")) continue
      if (code.includes("DOCTYPE")) continue

      let action = detectActionNear(content, m.index)
      let date = detectDateNear(content, m.index)
      let suspicious = isSuspiciousProfile(code)

      events.push({
        action,
        code,
        date,
        file,
        suspicious
      })
    }
  }

  return events
}

function uniqueEvents(events) {
  let map = {}

  for (let ev of events) {
    let key = `${ev.action}|${ev.code}|${ev.date}`
    map[key] = ev
  }

  return Object.values(map)
}

function scanJailbreak(content, file) {
  let found = []
  let lower = content.toLowerCase()

  for (let word of JAILBREAK_WORDS) {
    if (lower.includes(word.toLowerCase())) {
      found.push({
        indicator: word,
        file
      })
    }
  }

  return found
}

function getDeviceInfo(allText) {
  let info = {
    model: "iPhone OS",
    ios: "Não encontrado",
    serial: "Não encontrado"
  }

  let iosMatch =
    allText.match(/ProductVersion["\s:=<string>]+([0-9.]+)/i) ||
    allText.match(/iPhone OS\s+([0-9._]+)/i) ||
    allText.match(/iOS\s+([0-9.]+)/i)

  if (iosMatch) info.ios = iosMatch[1].replace(/_/g, ".")

  let serialMatch =
    allText.match(/SerialNumber["\s:=<string>]+([A-Z0-9]{8,20})/i) ||
    allText.match(/Serial Number["\s:=]+([A-Z0-9]{8,20})/i)

  if (serialMatch) info.serial = serialMatch[1]

  return info
}

function generateHtml(data) {
  let installed = data.events.filter(e => e.action === "Instalação")
  let removed = data.events.filter(e => e.action === "Remoção")
  let abnormal = data.events.filter(e => e.suspicious)

  function card(ev) {
    let cls = ev.action === "Remoção" ? "remove" : ev.action === "Instalação" ? "install" : "event"
    return `
      <div class="card">
        <div>
          <span class="tag ${cls}">${ev.action}</span>
          <div class="code">${ev.code}</div>
          <div class="file">${ev.file.split("/").pop()}</div>
        </div>
        <div class="date">${ev.date}</div>
      </div>
    `
  }

  return `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Hooking Scanner</title>
<style>
body {
  background:#050505;
  color:#eee;
  font-family: Menlo, monospace;
  padding:22px;
}
h1 {
  letter-spacing:5px;
  font-size:28px;
}
.section {
  border:1px solid #222;
  padding:18px;
  margin:22px 0;
  background:#080808;
}
.title {
  color:#888;
  letter-spacing:5px;
  margin-bottom:18px;
}
.row {
  display:flex;
  justify-content:space-between;
  border-bottom:1px solid #111;
  padding:12px 0;
}
.label { color:#888; }
.value { color:#fff; }
.card {
  border:1px solid #181818;
  padding:14px;
  margin:12px 0;
  display:flex;
  justify-content:space-between;
  gap:12px;
  background:#0b0b0b;
}
.tag {
  padding:5px 10px;
  border-radius:4px;
  font-size:12px;
}
.install {
  background:#063b1e;
  color:#6bff9e;
}
.remove {
  background:#410610;
  color:#ff5c72;
}
.event {
  background:#302406;
  color:#ffd76b;
}
.code {
  margin-top:12px;
  color:#fff;
  font-size:16px;
  word-break:break-all;
}
.file {
  margin-top:8px;
  color:#555;
  font-size:12px;
}
.date {
  color:#aaa;
  white-space:nowrap;
  font-size:13px;
}
.danger {
  color:#ff4f68;
  font-weight:bold;
}
.small {
  color:#555;
  font-size:12px;
}
</style>
</head>
<body>

<h1>ANALISANDO <span class="small">SCANNER</span></h1>

<div class="section">
  <div class="title">◆ INFORMAÇÕES DO DISPOSITIVO</div>
  <div class="row"><span class="label">Modelo</span><span class="value">${data.device.model}</span></div>
  <div class="row"><span class="label">iOS</span><span class="value">${data.device.ios}</span></div>
  <div class="row"><span class="label">Serial</span><span class="value">${data.device.serial}</span></div>
  <div class="row"><span class="label">Arquivos lidos</span><span class="value">${data.filesRead}</span></div>
</div>

<div class="section">
  <div class="title">◆ PERFIS INSTALADOS (${installed.length})</div>
  ${installed.length ? installed.map(card).join("") : "<p>Nenhum perfil instalado encontrado.</p>"}
</div>

<div class="section">
  <div class="title">◆ DETECÇÕES (${data.jailbreak.length})</div>
  ${data.jailbreak.length ? data.jailbreak.map(j => `
    <div class="card">
      <div>
        <span class="tag remove">Detectado</span>
        <div class="code">${j.indicator}</div>
        <div class="file">${j.file.split("/").pop()}</div>
      </div>
    </div>
  `).join("") : "<p>Nenhum indicador de jailbreak/hook encontrado.</p>"}
</div>

<div class="section">
  <div class="title">◆ PERFIS ANORMAIS (${abnormal.length})</div>
  ${abnormal.length ? abnormal.map(e => `
    <div class="card">
      <div class="danger">⚠ ${e.code}</div>
      <div class="date">${e.date}</div>
    </div>
  `).join("") : "<p>Nenhum perfil anormal encontrado.</p>"}
</div>

<div class="section">
  <div class="title">◆ INSTALAÇÃO DE PERFIS</div>
  ${data.events.length ? data.events.map(card).join("") : "<p>Nenhum evento encontrado.</p>"}
</div>

</body>
</html>
`
}

async function getInputPath() {
  await alertMsg("Hooking", "Selecione a pasta extraída da sysdiagnose e toque em Abrir.")
  return await DocumentPicker.openFolder()
}

async function main() {
  let fm = FileManager.local()
  let input = await getInputPath()

  let files = fm.isDirectory(input) ? walkDirectory(fm, input) : [input]

  let allEvents = []
  let jailbreak = []
  let allText = ""
  let filesRead = 0

  for (let file of files) {
    if (!isTextFile(file)) continue

    let content = readTextSafe(fm, file)
    if (!content) continue

    filesRead++

    if (file.toLowerCase().includes("mcsettingsevents") || content.toLowerCase().includes("systemprofilerestrictions")) {
      allEvents.push(...extractMCSettingsProfiles(content, file))
    }

    jailbreak.push(...scanJailbreak(content, file))

    if (allText.length < 2000000) {
      allText += "\n" + content.slice(0, 50000)
    }
  }

  let cleanEvents = uniqueEvents(allEvents)

  cleanEvents.sort((a, b) => {
    if (a.suspicious && !b.suspicious) return -1
    if (!a.suspicious && b.suspicious) return 1
    return a.code.localeCompare(b.code)
  })

  let device = getDeviceInfo(allText)

  let html = generateHtml({
    events: cleanEvents,
    jailbreak,
    device,
    filesRead
  })

  let outFM = FileManager.iCloud()
  let dir = outFM.documentsDirectory()
  let path = outFM.joinPath(dir, `hooking_result_${Date.now()}.html`)

  outFM.writeString(path, html)

  await alertMsg("Hooking finalizado", `Foram lidos ${filesRead} arquivos.\nRelatório visual gerado.`)

  QuickLook.present(path)
}

await main()
