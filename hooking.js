// HOOKING - Sysdiagnose Scanner para Scriptable

const RULES = [
  {
    name: "Frida",
    patterns: ["frida", "frida-server", "re.frida.server"],
    risk: 35
  },
  {
    name: "Dopamine",
    patterns: ["dopamine", "/var/jb", "ellekit"],
    risk: 40
  },
  {
    name: "MobileSubstrate",
    patterns: ["mobilesubstrate", "substrate", "cydiasubstrate"],
    risk: 35
  },
  {
    name: "Substitute",
    patterns: ["substitute", "libsubstitute"],
    risk: 30
  },
  {
    name: "Libhooker",
    patterns: ["libhooker"],
    risk: 30
  },
  {
    name: "Cydia",
    patterns: ["cydia", "/applications/cydia.app"],
    risk: 35
  },
  {
    name: "Sileo",
    patterns: ["sileo", "/applications/sileo.app"],
    risk: 35
  },
  {
    name: "TrollStore",
    patterns: ["trollstore", "com.opa334.trollstore"],
    risk: 30
  },
  {
    name: "Debug / LLDB",
    patterns: ["ptrace", "debugserver", "lldb", "gdb"],
    risk: 20
  }
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
    } else {
      if (isTextFile(path)) {
        files.push(path)
      }
    }
  }

  return files
}

function getPlistValue(content, key) {
  let regex = new RegExp(`<key>${key}<\\/key>\\s*<string>(.*?)<\\/string>`, "i")
  let match = content.match(regex)
  return match ? match[1].trim() : null
}

function extractProfiles(content) {
  let profiles = []
  let blocks = content.match(/<dict>[\s\S]*?<key>PayloadIdentifier<\/key>[\s\S]*?<\/dict>/gi) || []

  for (let block of blocks) {
    profiles.push({
      name: getPlistValue(block, "PayloadDisplayName") || "Não encontrado",
      identifier: getPlistValue(block, "PayloadIdentifier") || "Não encontrado",
      uuid: getPlistValue(block, "PayloadUUID") || "Não encontrado",
      organization: getPlistValue(block, "PayloadOrganization") || "Não encontrado",
      type: getPlistValue(block, "PayloadType") || "Não encontrado"
    })
  }

  return profiles
}

function extractEvents(content) {
  let events = []
  let lines = content.split(/\r?\n/)

  let keywords = [
    "profile installed",
    "profile removed",
    "installed profile",
    "removed profile",
    "mcprofile",
    "mcsettings",
    "configuration profile",
    "PayloadIdentifier",
    "PayloadUUID"
  ]

  for (let line of lines) {
    let lower = line.toLowerCase()

    if (keywords.some(k => lower.includes(k.toLowerCase()))) {
      let dateMatch =
        line.match(/\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/) ||
        line.match(/\d{2}\/\d{2}\/\d{4}[ T]\d{2}:\d{2}:\d{2}/) ||
        line.match(/\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/)

      events.push({
        date: dateMatch ? dateMatch[0] : "Data não encontrada",
        line: line.trim()
      })
    }
  }

  return events
}

function scanIndicators(content) {
  let findings = []
  let lower = content.toLowerCase()

  for (let rule of RULES) {
    let matched = []

    for (let p of rule.patterns) {
      if (lower.includes(p.toLowerCase())) {
        matched.push(p)
      }
    }

    if (matched.length) {
      findings.push({
        name: rule.name,
        patterns: matched,
        risk: rule.risk
      })
    }
  }

  return findings
}

function uniqueProfiles(profiles) {
  let map = {}

  for (let p of profiles) {
    let key = `${p.identifier}-${p.uuid}`
    map[key] = p
  }

  return Object.values(map)
}

function generateReport(data) {
  let score = Math.min(100, data.findings.reduce((s, f) => s + f.risk, 0))
  let status = score >= 70 ? "ALTO RISCO" : score >= 35 ? "RISCO MÉDIO" : "BAIXO RISCO"

  let report = ""
  report += "HOOKING - RELATÓRIO SYS DIAGNOSE iOS\n"
  report += "=====================================\n\n"
  report += `Data da análise: ${new Date().toLocaleString()}\n`
  report += `Arquivos lidos: ${data.filesRead}\n`
  report += `Score: ${score}/100\n`
  report += `Status: ${status}\n\n`

  report += "PERFIS ENCONTRADOS\n"
  report += "------------------\n"

  if (!data.profiles.length) {
    report += "Nenhum perfil encontrado.\n\n"
  } else {
    for (let p of data.profiles) {
      report += `Nome: ${p.name}\n`
      report += `Código/Identificador: ${p.identifier}\n`
      report += `UUID: ${p.uuid}\n`
      report += `Organização: ${p.organization}\n`
      report += `Tipo: ${p.type}\n\n`
    }
  }

  report += "INSTALAÇÕES / REMOÇÕES / EVENTOS MCSETTINGS-MCPROFILE\n"
  report += "------------------------------------------------------\n"

  if (!data.events.length) {
    report += "Nenhum evento encontrado.\n\n"
  } else {
    for (let ev of data.events.slice(0, 300)) {
      report += `Data/Hora: ${ev.date}\n`
      report += `Linha: ${ev.line}\n\n`
    }

    if (data.events.length > 300) {
      report += `...mais ${data.events.length - 300} eventos ocultados para evitar relatório gigante.\n\n`
    }
  }

  report += "JAILBREAK / HOOK / FRIDA / DOPAMINE\n"
  report += "------------------------------------\n"

  if (!data.findings.length) {
    report += "Nenhum indicador encontrado.\n\n"
  } else {
    for (let f of data.findings) {
      report += `Indicador: ${f.name}\n`
      report += `Padrões encontrados: ${f.patterns.join(", ")}\n`
      report += `Risco: ${f.risk}\n\n`
    }
  }

  report += "ARQUIVOS COM INDICADORES\n"
  report += "------------------------\n"

  if (!data.suspiciousFiles.length) {
    report += "Nenhum arquivo suspeito listado.\n"
  } else {
    for (let sf of data.suspiciousFiles.slice(0, 200)) {
      report += `Arquivo: ${sf.file}\n`
      report += `Achados: ${sf.matches.join(", ")}\n\n`
    }
  }

  return report
}

async function getInputPath() {
  if (args.fileURLs && args.fileURLs.length > 0) {
    return args.fileURLs[0].replace("file://", "")
  }

  await alertMsg(
    "Hooking",
    "Abra a pasta/arquivo extraído da sysdiagnose pelo app Arquivos e escolha Compartilhar > Scriptable."
  )

  let picked = await DocumentPicker.openFile()
  return picked
}

async function main() {
  let fm = FileManager.local()
  let input = await getInputPath()

  let files = []

  if (fm.isDirectory(input)) {
    files = walkDirectory(fm, input)
  } else {
    files = [input]
  }

  let allProfiles = []
  let allEvents = []
  let allFindings = []
  let suspiciousFiles = []
  let filesRead = 0

  for (let file of files) {
    if (!isTextFile(file)) continue

    let content = readTextSafe(fm, file)
    if (!content) continue

    filesRead++

    let profiles = extractProfiles(content)
    let events = extractEvents(content)
    let findings = scanIndicators(content)

    allProfiles.push(...profiles)
    allEvents.push(...events)
    allFindings.push(...findings)

    if (findings.length) {
      suspiciousFiles.push({
        file,
        matches: findings.map(f => f.name)
      })
    }
  }

  let report = generateReport({
    filesRead,
    profiles: uniqueProfiles(allProfiles),
    events: allEvents,
    findings: allFindings,
    suspiciousFiles
  })

  let outFM = FileManager.iCloud()
  let outDir = outFM.documentsDirectory()
  let outPath = outFM.joinPath(outDir, `hooking_sysdiagnose_${Date.now()}.txt`)

  outFM.writeString(outPath, report)

  await alertMsg(
    "Hooking finalizado",
    `Sysdiagnose analisada.\n\nArquivos lidos: ${filesRead}\nRelatório salvo em Documentos do Scriptable.`
  )

  QuickLook.present(outPath)
}

await main()
