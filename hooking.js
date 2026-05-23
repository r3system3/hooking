// HOOKING - Scanner MCProfile / MCSettingsEvents

const APP_NAME = "HOOKING"
const CREDIT = "SANTOS e r3"
const DISCORD = "discord.gg/hooking"

const TEXT_EXTENSIONS = [
  ".txt", ".log", ".ips", ".plist", ".mobileconfig",
  ".json", ".xml", ".trace", ".crash", ".analytics"
]

const PROFILE_SUSPICIOUS_WORDS = [
  "aimbot", "cheat", "hack", "freefire", "inject", "injected",
  "hook", "bypass", "mod", "apple-dns", "dns", "vpn", "proxy",
  "warp", "managed", "configuration"
]

const JAILBREAK_STRONG_WORDS = [
  "frida-server",
  "re.frida.server",
  "/var/jb/",
  "/applications/cydia.app",
  "/applications/sileo.app",
  "/applications/zebra.app",
  "mobilesubstrate.dylib",
  "cydiasubstrate",
  "libhooker.dylib",
  "libsubstitute.dylib",
  "ellekit.dylib",
  "dopamine.app",
  "trollstore.app"
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
    } else if (isTextFile(path) || path.toLowerCase().includes("mcsettings") || path.toLowerCase().includes("mcprofile")) {
      files.push(path)
    }
  }

  return files
}

function cleanText(s) {
  return String(s || "")
    .replace(/\u0000/g, "")
    .replace(/[^\x20-\x7EÀ-ÿ]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
}

function normalizeCode(code) {
  return cleanText(code)
    .replace(/^[-_\s]+/, "")
    .replace(/[-_\s]+$/, "")
}

function detectOperation(content, index) {
  let block = content.slice(Math.max(0, index - 900), Math.min(content.length, index + 900)).toLowerCase()

  let removePos = Math.max(
    block.lastIndexOf("remove"),
    block.lastIndexOf("removed"),
    block.lastIndexOf("removal"),
    block.lastIndexOf("remoção"),
    block.lastIndexOf("remocao")
  )

  let installPos = Math.max(
    block.lastIndexOf("install"),
    block.lastIndexOf("installed"),
    block.lastIndexOf("instalação"),
    block.lastIndexOf("instalacao")
  )

  if (removePos > installPos && removePos !== -1) return "Remoção"
  if (installPos !== -1) return "Instalação"

  return "Evento"
}

function detectDate(content, index) {
  let block = content.slice(Math.max(0, index - 1200), Math.min(content.length, index + 1200))

  let found =
    block.match(/\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/) ||
    block.match(/\d{2}\/\d{2}\/\d{4}[, ]+\d{2}:\d{2}:\d{2}/) ||
    block.match(/\d{2}-\d{2}-\d{4}[, ]+\d{2}:\d{2}:\d{2}/)

  return found ? found[0] : "Timestamp interno"
}

function isSuspiciousProfile(code) {
  let lower = code.toLowerCase()
  return PROFILE_SUSPICIOUS_WORDS.some(w => lower.includes(w))
}

function extractProfileEvents(content, file) {
  let events = []
  let source = content

  let regexes = [
    /([a-f0-9]{40,96}-[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12})/g,
    /([A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}-[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12})/g,
    /((?:com\.)[a-zA-Z0-9._~\-]{4,160})/g,
    /([a-f0-9]{32,96})/g,
    /<key>([^<]{8,220})<\/key>\s*<dict>/gi,
    /<string>([^<]{8,220})<\/string>/gi
  ]

  for (let regex of regexes) {
    let m
    while ((m = regex.exec(source)) !== null) {
      let code = normalizeCode(m[1])

      if (!code) continue
      if (code.length < 8) continue
      if (code.toLowerCase().includes("doctype")) continue
      if (code.toLowerCase().includes("plist")) continue
      if (code.toLowerCase().includes("http")) continue
      if (code.toLowerCase().includes("apple.com/dtd")) continue

      let action = detectOperation(source, m.index)
      let date = detectDate(source, m.index)

      events.push({
        action,
        code,
        date,
        file,
        suspicious: isSuspiciousProfile(code)
      })
    }
  }

  return events
}

function uniqueEvents(events) {
  let map = {}
  for (let ev of events) {
    let key = `${ev.action}|${ev.code}`
    if (!map[key]) map[key] = ev
  }
  return Object.values(map)
}

function scanJailbreak(content, file) {
  let found = []
  let lower = content.toLowerCase()
  let filename = file.toLowerCase()

  for (let word of JAILBREAK_STRONG_WORDS) {
    if (lower.includes(word.toLowerCase()) || filename.includes(word.toLowerCase())) {
      found.push({ indicator: word, file })
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
<title>${APP_NAME}</title>
<style>
body {
  background:#050505;
  color:#eee;
  font-family: Menlo, monospace;
  padding:22px;
}
.main-name {
  color:#ffffff;
  font-size:42px;
  font-weight:900;
  letter-spacing:8px;
  text-shadow:0 0 12px #fff, 0 0 22px #777;
  margin-bottom:4px;
}
.credits {
  color:#777;
  font-size:12px;
  letter-spacing:3px;
  margin-bottom:20px;
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
  word-break:break-all;
}
</style>
</head>
<body>

<div class="main-name">${APP_NAME}</div>
<div class="credits">CRÉDITOS: ${CREDIT}<br>${DISCORD}</div>

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
  <div class="title">◆ PERFIS REMOVIDOS (${removed.length})</div>
  ${removed.length ? removed.map(card).join("") : "<p>Nenhum perfil removido encontrado.</p>"}
</div>

<div class="section">
  <div class="title">◆ DETECÇÕES JAILBREAK (${data.jailbreak.length})</div>
  ${data.jailbreak.length ? data.jailbreak.map(j => `
    <div class="card">
      <div>
        <span class="tag remove">Detectado</span>
        <div class="code">${j.indicator}</div>
        <div class="file">${j.file.split("/").pop()}</div>
      </div>
    </div>
  `).join("") : "<p>Nenhum indicador forte de jailbreak encontrado.</p>"}
</div>

<div class="section">
  <div class="title">◆ PERFIS ANORMAIS (${abnormal.length})</div>
  ${abnormal.length ? abnormal.map(e => `
    <div class="card">
      <div>
        <div class="danger">⚠ ${e.code}</div>
        <div class="file">${e.file.split("/").pop()}</div>
      </div>
      <div class="date">${e.date}</div>
    </div>
  `).join("") : "<p>Nenhum perfil anormal encontrado.</p>"}
</div>

<div class="section">
  <div class="title">◆ INSTALAÇÃO / REMOÇÃO DE PERFIS (${data.events.length})</div>
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
    let lowerFile = file.toLowerCase()
    if (!isTextFile(file) && !lowerFile.includes("mcsettings") && !lowerFile.includes("mcprofile")) continue

    let content = readTextSafe(fm, file)
    if (!content) continue

    filesRead++

    let lower = content.toLowerCase()

    if (
      lowerFile.includes("mcsettings") ||
      lowerFile.includes("mcprofile") ||
      lower.includes("profileevents") ||
      lower.includes("systemprofilerestrictions") ||
      lower.includes("operation") ||
      lower.includes("timestamp")
    ) {
      allEvents.push(...extractProfileEvents(content, file))
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
    if (a.action === "Remoção" && b.action !== "Remoção") return -1
    return a.code.localeCompare(b.code)
  })

  let html = generateHtml({
    events: cleanEvents,
    jailbreak,
    device: getDeviceInfo(allText),
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
