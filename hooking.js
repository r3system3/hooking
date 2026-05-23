// HOOKING 
// Créditos: SANTOS e r3
// Discord: discord.gg/hooking

const APP_NAME = "HOOKING"
const CREDIT = "SANTOS e r3"
const DISCORD = "discord.gg/hooking"

async function alertMsg(title, message) {
  let a = new Alert()
  a.title = title
  a.message = message
  a.addAction("OK")
  await a.present()
}

function isMCFile(path) {
  let lower = path.toLowerCase()

  return (
    lower.includes("mcsettingsevents") ||
    lower.includes("mcprofileevents") ||
    lower.includes("mcsettings") ||
    lower.includes("mcprofile") ||
    lower.includes("managedsettings") ||
    lower.includes("managedconfiguration")
  )
}

function getFileType(path) {
  let lower = path.toLowerCase()

  if (
    lower.includes("mcsettingsevents") ||
    lower.includes("mcsettings") ||
    lower.includes("managedsettings")
  ) {
    return "MCSettings"
  }

  if (
    lower.includes("mcprofileevents") ||
    lower.includes("mcprofile")
  ) {
    return "MCProfile"
  }

  return "MC"
}

function walkDirectory(fm, dir, files = []) {
  let items = fm.listContents(dir)

  for (let item of items) {
    let path = fm.joinPath(dir, item)

    if (fm.isDirectory(path)) {
      walkDirectory(fm, path, files)
    } else if (isMCFile(path)) {
      files.push(path)
    }
  }

  return files
}

function readTextSafe(fm, path) {
  try {
    return fm.readString(path)
  } catch (e) {
    return ""
  }
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

function uniqueEvents(events) {
  let map = {}

  for (let ev of events) {
    let key = `${ev.source}|${ev.action}|${ev.code}|${ev.date}|${ev.file}`
    if (!map[key]) map[key] = ev
  }

  return Object.values(map)
}

function findOperations(text) {
  let operations = []
  let operationRegex = /(install|installed|remove|removed|removal)/gi
  let op

  while ((op = operationRegex.exec(text)) !== null) {
    let raw = op[1].toLowerCase()

    operations.push({
      type: raw.includes("install") ? "Instalação" : "Remoção",
      index: op.index
    })
  }

  return operations
}

function findNearestOperation(operations, index, maxDistance) {
  let nearestOp = null
  let nearestDistance = Infinity

  for (let o of operations) {
    let distance = Math.abs(o.index - index)

    if (distance < nearestDistance && distance <= maxDistance) {
      nearestDistance = distance
      nearestOp = o
    }
  }

  return nearestOp
}

function extractDateNear(text, index) {
  let block = text.slice(Math.max(0, index - 2500), Math.min(text.length, index + 2500))

  let patterns = [
    /\d{2}\/\d{2}\/\d{4}[, ]+\d{2}:\d{2}:\d{2}/,
    /\d{2}-\d{2}-\d{4}[, ]+\d{2}:\d{2}:\d{2}/,
    /\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/,
    /\d{2}\/\d{2}\/\d{2}[, ]+\d{2}:\d{2}:\d{2}/
  ]

  for (let p of patterns) {
    let m = block.match(p)
    if (m) return m[0]
  }

  return "Data/hora não encontrada"
}

function isSystemNoise(code) {
  let lower = code.toLowerCase()

  let bad = [
    "apple.com/dtd",
    "doctype",
    "plist",
    "version",
    "encoding",
    "dict",
    "array",
    "string",
    "integer",
    "false",
    "true",
    "root",
    "timestamp",
    "operation",
    "process"
  ]

  if (bad.some(b => lower.includes(b))) return true
  if (lower.length < 8) return true

  return false
}

function classifyCode(code) {
  let lower = code.toLowerCase()

  if (/^[a-f0-9]{64,128}$/i.test(code)) return "Hash/Certificado"
  if (/^[a-f0-9]{40,128}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(code)) return "Hash + UUID"
  if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(code)) return "UUID"
  if (lower.startsWith("com.")) return "Bundle/Profile"
  if (lower.startsWith("xyz.")) return "Profile XYZ"
  if (lower.startsWith("net.")) return "Profile NET"
  if (lower.startsWith("org.")) return "Profile ORG"
  if (lower.includes("khoindvn") || lower.includes("khoivdon")) return "Perfil DNS/Khoindvn"

  return "Código/Perfil"
}

function isInterestingCode(code) {
  let lower = code.toLowerCase()

  if (isSystemNoise(code)) return false

  if (/^[a-f0-9]{64,128}$/i.test(code)) return true
  if (/^[a-f0-9]{40,128}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(code)) return true
  if (/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(code)) return true

  if (/^(com|xyz|net|org)\.[a-zA-Z0-9._~\-]{4,220}$/i.test(code)) return true

  if (lower.includes("khoindvn")) return true
  if (lower.includes("khoivdon")) return true
  if (lower.includes("apple-dns")) return true
  if (lower.includes("fatality")) return true
  if (lower.includes("freefire")) return true
  if (lower.includes("aimbot")) return true
  if (lower.includes("vpn")) return true
  if (lower.includes("dns")) return true

  return false
}

function extractCodesFromText(text) {
  let codes = []

  let regexes = [
    /([a-f0-9]{40,128}-[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12})/gi,
    /([a-f0-9]{64,128})/gi,
    /([A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12})/gi,
    /((?:com|xyz|net|org)\.[a-zA-Z0-9._~\-]{4,220})/g,
    /([a-zA-Z0-9._~\-]*khoindvn[a-zA-Z0-9._~\-]*)/gi,
    /([a-zA-Z0-9._~\-]*khoivdon[a-zA-Z0-9._~\-]*)/gi
  ]

  for (let regex of regexes) {
    let m

    while ((m = regex.exec(text)) !== null) {
      let code = normalizeCode(m[1])

      if (!code) continue
      if (!isInterestingCode(code)) continue

      codes.push({
        code,
        index: m.index,
        type: classifyCode(code)
      })
    }
  }

  return codes
}

function extractProfileCodes(content, file) {
  let events = []
  let source = getFileType(file)
  let text = cleanText(content)

  let operations = findOperations(text)
  let codes = extractCodesFromText(text)

  let maxDistance = source === "MCSettings" ? 9000 : 5000

  for (let c of codes) {
    let nearestOp = findNearestOperation(operations, c.index, maxDistance)

    if (!nearestOp) {
      continue
    }

    events.push({
      source,
      action: nearestOp.type,
      code: c.code,
      codeType: c.type,
      date: extractDateNear(text, c.index),
      file,
      position: c.index
    })
  }

  return uniqueEvents(events)
}

function generateHtml(data) {
  let installed = data.events.filter(e => e.action === "Instalação")
  let removed = data.events.filter(e => e.action === "Remoção")
  let mcSettings = data.events.filter(e => e.source === "MCSettings")
  let mcProfile = data.events.filter(e => e.source === "MCProfile")

  function card(ev) {
    let cls = ev.action === "Remoção" ? "remove" : "install"

    return `
      <div class="card">
        <div class="card-main">
          <span class="tag ${cls}">${ev.action}</span>
          <span class="source">${ev.source}</span>
          <span class="type">${ev.codeType}</span>
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
  background:#0b0b0b;
  display:flex;
  justify-content:space-between;
  gap:16px;
}
.card-main {
  flex:1;
  min-width:0;
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
.source {
  color:#ffd56b;
  margin-left:8px;
  font-size:12px;
}
.type {
  color:#777;
  margin-left:8px;
  font-size:12px;
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
  text-align:right;
}
</style>
</head>
<body>

<div class="main-name">${APP_NAME}</div>
<div class="credits">CRÉDITOS: ${CREDIT}<br>${DISCORD}</div>

<div class="section">
  <div class="title">◆ ARQUIVOS ANALISADOS</div>
  <div class="row"><span class="label">MCSettings / MCProfile lidos</span><span class="value">${data.filesRead}</span></div>
  <div class="row"><span class="label">Eventos encontrados</span><span class="value">${data.events.length}</span></div>
  <div class="row"><span class="label">MCSettings detectados</span><span class="value">${mcSettings.length}</span></div>
  <div class="row"><span class="label">MCProfile detectados</span><span class="value">${mcProfile.length}</span></div>
</div>

<div class="section">
  <div class="title">◆ PERFIS INSTALADOS (${installed.length})</div>
  ${installed.length ? installed.map(card).join("") : "<p>Nenhuma instalação encontrada.</p>"}
</div>

<div class="section">
  <div class="title">◆ PERFIS REMOVIDOS (${removed.length})</div>
  ${removed.length ? removed.map(card).join("") : "<p>Nenhuma remoção encontrada.</p>"}
</div>

<div class="section">
  <div class="title">◆ MCSETTINGS (${mcSettings.length})</div>
  ${mcSettings.length ? mcSettings.map(card).join("") : "<p>Nenhum evento encontrado na MCSettings.</p>"}
</div>

<div class="section">
  <div class="title">◆ MCPROFILE (${mcProfile.length})</div>
  ${mcProfile.length ? mcProfile.map(card).join("") : "<p>Nenhum evento encontrado na MCProfile.</p>"}
</div>

<div class="section">
  <div class="title">◆ TODOS OS EVENTOS (${data.events.length})</div>
  ${data.events.length ? data.events.map(card).join("") : "<p>Nenhum código com install/remove encontrado.</p>"}
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
  let filesRead = 0

  for (let file of files) {
    if (!isMCFile(file)) continue

    let content = readTextSafe(fm, file)
    if (!content) continue

    filesRead++

    let extracted = extractProfileCodes(content, file)
    allEvents.push(...extracted)
  }

  let cleanEvents = uniqueEvents(allEvents)

  cleanEvents.sort((a, b) => {
    if (a.source === "MCSettings" && b.source !== "MCSettings") return -1
    if (a.source !== "MCSettings" && b.source === "MCSettings") return 1
    if (a.action === "Instalação" && b.action !== "Instalação") return -1
    if (a.action === "Remoção" && b.action !== "Remoção") return 1
    return a.code.localeCompare(b.code)
  })

  let html = generateHtml({
    events: cleanEvents,
    filesRead
  })

  let outFM = FileManager.iCloud()
  let dir = outFM.documentsDirectory()
  let path = outFM.joinPath(dir, `hooking_result_${Date.now()}.html`)

  outFM.writeString(path, html)

  await alertMsg(
    "Hooking finalizado",
    `Arquivos MC lidos: ${filesRead}\nEventos encontrados: ${cleanEvents.length}`
  )

  QuickLook.present(path)
}

await main()
