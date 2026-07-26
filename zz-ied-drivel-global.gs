/**
 * Auditoría Avanzada de Seguridad en Google Workspace (NIVEL ORGANIZACIONAL)
 * VERSIÓN DRIVE API v3 + DWD (Domain-Wide Delegation) con AuthService y Secret Manager
 */

function AuditoriaIEDriveCorporativo() {
  const MAX_EXEC_TIME_MS = 4.5 * 60 * 1000; 
  Logger.log("=== INICIANDO AUDITORÍA IED CORPORATIVA EN DRIVE ===");
  
  let ui = null;
  try { ui = SpreadsheetApp.getUi(); } catch (e) {}

  const auth = new AuthService();
  const customerId = auth.getCustomerId();
  const CORPORATE_DOMAIN = auth.getDomain();

  const scriptProperties = PropertiesService.getScriptProperties();
  
  // ESTADO DE EJECUCIÓN (Para pausar y reanudar de forma transparente)
  let isFinished = scriptProperties.getProperty('isFinished');
  let userPageToken = scriptProperties.getProperty('userPageToken') || null;
  let currentImpersonatedUser = scriptProperties.getProperty('currentImpersonatedUser') || null;
  let drivePageToken = scriptProperties.getProperty('drivePageToken') || null;

  if (isFinished === 'true') {
    if (ui) ui.alert("✅ La auditoría corporativa de Drive ya está completa.");
    return;
  }

  // Si es el inicio absoluto del proceso, preparamos la pestaña de Sheets
  if (!currentImpersonatedUser && !userPageToken && !drivePageToken) {
    inicializarHojaIED();
  }

  // Calcular la fecha límite: hace 1 año exacto (Formato RFC 3339 exigido por Drive API v3)
  let unAnoAtras = new Date();
  unAnoAtras.setFullYear(unAnoAtras.getFullYear() - 1);
  const fechaLimite = unAnoAtras.toISOString();

  const startTime = Date.now(); 
  const SCOPES = ["https://www.googleapis.com/auth/drive.readonly"];

  let currentUserList = [];
  let userListIndex = parseInt(scriptProperties.getProperty('userListIndex') || "0", 10);

  // Bucle Principal: Ejecuta mientras haya tiempo disponible antes de alcanzar el límite del script
  while (Date.now() - startTime < MAX_EXEC_TIME_MS) { 
    
    // 1. OBTENER UN USUARIO SI NO ESTAMOS PROCESANDO UNO ACTUALMENTE
    if (!currentImpersonatedUser) {
      if (currentUserList.length === 0 || userListIndex >= currentUserList.length) {
        let optionalArgs = { 
          customer: customerId, 
          maxResults: 100, 
          projection: "basic" 
        };
        if (userPageToken) optionalArgs.pageToken = userPageToken;
        
        let responseUsers;
        try {
          responseUsers = AdminDirectory.Users.list(optionalArgs);
        } catch (e) {
          Logger.log("[ERROR CRÍTICO ADMIN SDK] No se pudieron listar usuarios de la organización: " + e.message);
          isFinished = 'error';
          break;
        }

        let users = responseUsers.users || [];
        userPageToken = responseUsers.nextPageToken || null;
        userListIndex = 0;

        if (users.length === 0) {
          isFinished = 'true';
          break;
        }

        // Seleccionar correos primarios de usuarios no suspendidos
        currentUserList = users
          .filter(u => !u.suspended && u.primaryEmail)
          .map(u => u.primaryEmail);

        if (currentUserList.length === 0) {
          if (!userPageToken) {
            isFinished = 'true';
            break;
          } else {
            continue;
          }
        }
      }

      currentImpersonatedUser = currentUserList[userListIndex];
      userListIndex++;
      drivePageToken = null;
      Logger.log(`[CAMBIO DE USUARIO] Iniciando escaneo para: ${currentImpersonatedUser} (${userListIndex}/${currentUserList.length})`);
    }

    // 2. OBTENER CABECERA DE AUTENTICACIÓN CON DWD (Vía AuthService & GCP Secret Manager)
    let authHeader;
    try {
      authHeader = auth.getPrivilegedAuthHeader(currentImpersonatedUser, SCOPES);
    } catch (e) {
      Logger.log(`[ERROR DWD] No se pudo generar token de acceso privilegiado para ${currentImpersonatedUser}: ${e.message}. Saltando...`);
      currentImpersonatedUser = null;
      drivePageToken = null;
      continue;
    }

    // 3. CONSULTAR LA API DE DRIVE PARA EL USUARIO IMPERSONADO
    // q: Solo archivos de los que ES PROPIETARIO (evita duplicados) y modificados en el último año
    let query = `'me' in owners and trashed=false and modifiedTime >= '${fechaLimite}'`;
    let fields = "nextPageToken, files(id, name, mimeType, modifiedTime, owners, permissions(id, type, role, emailAddress, domain, allowFileDiscovery))";
    
    let url = `https://www.googleapis.com/drive/v3/files?pageSize=1000&fields=${encodeURIComponent(fields)}&q=${encodeURIComponent(query)}`;
    if (drivePageToken) url += `&pageToken=${encodeURIComponent(drivePageToken)}`;

    // Ejecutar con Backoff Exponencial adaptado
    let authBearerToken = authHeader["Authorization"];
    let responseText = ejecutarDriveAPIConBackoffRest(url, authBearerToken);
    
    if (!responseText) {
      Logger.log(`[ERROR API / DENEGADO] Fallo o permisos insuficientes al consultar Drive para ${currentImpersonatedUser}. Saltando usuario.`);
      currentImpersonatedUser = null;
      drivePageToken = null;
      continue;
    }

    let responseData;
    try {
      responseData = JSON.parse(responseText);
    } catch (e) {
      Logger.log(`[ERROR PARSE JSON] Respuesta no válida de Drive API para ${currentImpersonatedUser}`);
      currentImpersonatedUser = null;
      drivePageToken = null;
      continue;
    }

    if (responseData.error) {
      Logger.log(`[ERROR DRIVE API] ${responseData.error.message || JSON.stringify(responseData.error)} para usuario ${currentImpersonatedUser}. Saltando usuario...`);
      currentImpersonatedUser = null;
      drivePageToken = null;
      continue;
    }

    let files = responseData.files || [];
    
    if (files.length > 0) {
      Logger.log(`[PROCESANDO] ${files.length} archivos de ${currentImpersonatedUser}...`);
      let procesados = procesarArchivosDriveV3(files, CORPORATE_DOMAIN);
      if (procesados.length > 0) {
        escribirEnHojaActiva(procesados);
        SpreadsheetApp.flush(); 
      }
    }

    drivePageToken = responseData.nextPageToken || null; 
    
    // Si no hay más páginas para este usuario, avanzamos al siguiente
    if (!drivePageToken) {
      Logger.log(`[INFO] Escaneo completado para: ${currentImpersonatedUser}`);
      currentImpersonatedUser = null; 
    }
    
    // Si no hay más usuarios ni tokens pendientes
    if (!currentImpersonatedUser && (currentUserList.length === 0 || userListIndex >= currentUserList.length) && !userPageToken) {
      isFinished = 'true';
      break;
    }
  }

  // ===============================================
  // LÓGICA DE PERSISTENCIA Y CONTINUIDAD ASÍNCRONA
  // ===============================================
  if (isFinished === 'true') {
    scriptProperties.deleteAllProperties();
    scriptProperties.setProperty('isFinished', 'true');
    Logger.log("=== AUDITORÍA IED CORPORATIVA COMPLETADA CON ÉXITO ===");
    
    crearTablaResumenM(); // Invocación de la tabla resumen en la hoja activa
    if (ui) ui.alert("✅ Auditoría Corporativa Drive completada con éxito.");
  } else if (isFinished === 'error') {
    scriptProperties.deleteAllProperties();
    Logger.log("=== AUDITORÍA INTERRUMPIDA POR ERROR DE CONFIGURACIÓN ===");
  } else {
    // Guardar estado en PropertiesService para la siguiente iteración
    if (userPageToken) scriptProperties.setProperty('userPageToken', userPageToken);
    else scriptProperties.deleteProperty('userPageToken');
    
    if (currentImpersonatedUser) scriptProperties.setProperty('currentImpersonatedUser', currentImpersonatedUser);
    else scriptProperties.deleteProperty('currentImpersonatedUser');

    if (drivePageToken) scriptProperties.setProperty('drivePageToken', drivePageToken);
    else scriptProperties.deleteProperty('drivePageToken');

    scriptProperties.setProperty('userListIndex', userListIndex.toString());

    // Eliminar disparadores temporales antiguos
    let triggers = ScriptApp.getProjectTriggers();
    triggers.forEach(trigger => {
      if(trigger.getHandlerFunction() === 'AuditoriaIEDriveCorporativo') ScriptApp.deleteTrigger(trigger);
    });

    // Programar disparador para continuar en 1 minuto
    ScriptApp.newTrigger('AuditoriaIEDriveCorporativo') 
             .timeBased()
             .after(1 * 60 * 1000) 
             .create();
  }
}

// ==========================================
// RETROCESO EXPONENCIAL ADAPTADO A REST (UrlFetchApp)
// ==========================================
function ejecutarDriveAPIConBackoffRest(url, authHeaderValue) {
  let intentos = 0;
  let maxIntentos = 5; 
  
  while (intentos < maxIntentos) {
    try {
      let response = UrlFetchApp.fetch(url, {
        method: 'get',
        headers: { 'Authorization': authHeaderValue },
        muteHttpExceptions: true
      });
      
      let code = response.getResponseCode();
      if (code === 200) {
        return response.getContentText();
      } else if (code === 403 || code === 429 || code >= 500) {
        let content = response.getContentText();
        // Si el usuario no tiene habilitada la API de Drive o no tiene licencia, no reintentamos interminablemente
        if (content.includes("userAccessRefused") || content.includes("domainCannotUseDrive") || content.includes("notAuthorized")) {
          Logger.log(`[API PERMISOS DENEGADOS] HTTP ${code}: ${content}`);
          return null;
        }

        let pausa = Math.pow(2, intentos) * 1000 + (Math.random() * 1000); 
        Logger.log(`[API LIMIT / SERVIDOR] HTTP ${code}. Hibernando ${Math.round(pausa)}ms (Intento ${intentos + 1})`);
        Utilities.sleep(pausa); 
        intentos++;
      } else {
        Logger.log(`[API HTTP ERROR NO RECUPERABLE] Code: ${code} - ${response.getContentText()}`);
        return null;
      }
      
    } catch (e) {
      let errorMsg = e.message.toLowerCase();
      if (errorMsg.includes('403') || errorMsg.includes('429') || errorMsg.includes('rate limit') || errorMsg.includes('500')) {
        let pausa = Math.pow(2, intentos) * 1000 + (Math.random() * 1000); 
        Logger.log(`[API LIMIT] Cuota excedida o fallo temporal. Hibernando ${Math.round(pausa)}ms (Intento ${intentos + 1})`);
        Utilities.sleep(pausa); 
        intentos++;
      } else {
        Logger.log(`[API ERROR NO RECUPERABLE] ${e.message}`);
        return null;
      }
    }
  }
  return null; 
}

// ==========================================
// PREPARACIÓN DE PESTAÑA CORPORATIVA (10 COLUMNAS)
// ==========================================
function inicializarHojaIED() {
  const SHEET_NAME = "Auditoria Corporativa IED";
  let ss = SpreadsheetApp.getActiveSpreadsheet();
  if (!ss) return;
  let sheet = ss.getSheetByName(SHEET_NAME);
  
  if (sheet) {
    sheet.clear(); 
  } else {
    sheet = ss.insertSheet(SHEET_NAME);
  }
  
  sheet.appendRow([
    "Fecha Modificación", 
    "Actor (Propietario)", 
    "Aplicación", 
    "ID Documento", 
    "Titulo del recurso", 
    "Visibilidad/Severidad", 
    "Destinatario(s)", 
    "Compartido con Externo", 
    "Cualquiera con el Enlace", 
    "Criterio de Riesgo"
  ]);
  sheet.getRange(1, 1, 1, 10).setFontWeight("bold").setBackground("#edf2f7");
}

// ==========================================
// PROCESAMIENTO DE ACL DE ARCHIVOS DRIVE v3
// ==========================================
function procesarArchivosDriveV3(files, corporateDomain) {
  const CORPORATE_DOMAIN = corporateDomain || "test.apisas.com";
  let filas = [];

  files.forEach(file => {
    try {
      let actorEmail = "Desconocido";
      if (file.owners && file.owners.length > 0) {
        actorEmail = file.owners[0].emailAddress || "Desconocido"; 
      }

      let permissions = file.permissions || []; 
      
      let destinatariosSet = new Set();
      let compartidoExternoFlag = false;
      let anyoneFlag = false;
      let publicOnWebFlag = false;
      let domainFlag = false;

      permissions.forEach(perm => {
        if (perm.role === 'owner') return; 

        if (perm.type === 'anyone') {
          anyoneFlag = true; 
          destinatariosSet.add("Cualquiera (Anyone)"); 
          if (perm.allowFileDiscovery) publicOnWebFlag = true; 
        } else if (perm.type === 'user' || perm.type === 'group') {
          let email = perm.emailAddress || "";
          let domain = perm.domain || "";
          
          if (email) destinatariosSet.add(email);

          if (domain && domain.toLowerCase() !== CORPORATE_DOMAIN.toLowerCase()) {
            compartidoExternoFlag = true;
          } else if (email) {
            let partes = email.split('@');
            if (partes.length === 2 && partes[1].toLowerCase() !== CORPORATE_DOMAIN.toLowerCase()) {
              compartidoExternoFlag = true; 
            }
          }
        } else if (perm.type === 'domain') {
          domainFlag = true;
          if (perm.domain && perm.domain.toLowerCase() !== CORPORATE_DOMAIN.toLowerCase()) {
             compartidoExternoFlag = true;
             destinatariosSet.add(`[Dominio Externo: ${perm.domain}]`);
          }
        }
      });

      let destinatarios = Array.from(destinatariosSet);

      if (destinatarios.length === 0 && domainFlag) {
        destinatarios.push("Toda la organización");
      }

      // Solo registrar recursos que tengan permisos de compartición
      if (destinatarios.length === 0 && !anyoneFlag && !domainFlag) return; 

      let visibilidad = "Private";
      if (anyoneFlag && publicOnWebFlag) visibilidad = "public_on_the_web"; 
      else if (anyoneFlag) visibilidad = "people_with_link"; 
      else if (domainFlag && !compartidoExternoFlag) visibilidad = "people_within_domain_with_link"; 
      else if (domainFlag || compartidoExternoFlag) visibilidad = "externally";
      else if (destinatarios.length > 0) visibilidad = "shared_internally"; 

      let strCualquiera = anyoneFlag ? "Sí" : "No";
      let strExterno = compartidoExternoFlag ? "Sí" : "No";

      let riesgo = anyoneFlag ? "Alto" : (compartidoExternoFlag ? "Medio" : "Bajo");

      let fechaModificacion = file.modifiedTime ? Utilities.formatDate(new Date(file.modifiedTime), "America/Bogota", "yyyy-MM-dd HH:mm:ss") : "N/A";

      filas.push([
        fechaModificacion, actorEmail, "Google Drive", file.id, file.name, 
        visibilidad, destinatarios.join(', '), strExterno, strCualquiera, riesgo
      ]);

    } catch (e) {
      Logger.log(`[ERROR EN ARCHIVO] ${e.message}`);
    }
  });

  return filas;
}

// ==========================================
// ESCRITURA EN BATCH EN GOOGLE SHEETS
// ==========================================
function escribirEnHojaActiva(matrizDatos) {
  const SHEET_NAME = "Auditoria Corporativa IED";
  let ss = SpreadsheetApp.getActiveSpreadsheet();
  if (!ss) return;
  let sheet = ss.getSheetByName(SHEET_NAME);
  if (!sheet) return; 
  
  let ultimaFila = Math.max(sheet.getLastRow(), 1); 
  try {
    sheet.getRange(ultimaFila + 1, 1, matrizDatos.length, matrizDatos[0].length).setValues(matrizDatos);
  } catch (e) {
    Logger.log(`[ERROR DE ESCRITURA]: ${e.message}`);
  }
}

// ==========================================
// TABLA DE CONTROL RESUMEN CON FORMULAS E IED
// ==========================================
function crearTablaResumenM() {
  const SHEET_NAME = "Auditoria Corporativa IED";
  let ss = SpreadsheetApp.getActiveSpreadsheet();
  if (!ss) return;
  let sheet = ss.getSheetByName(SHEET_NAME);
  if (!sheet) return;

  let resumenMatriz = [
    ["Resumen de Reglas e Índice de Exposición (Corp)", "", ""],
    ["Criterio de Riesgo", "Cantidad de Archivos", "Porcentaje (%)"],
    ["🔴 Alto", '=COUNTIF(J2:J, "Alto")', '=IF(N$7>0, N4/N$7, 0)'],
    ["🟡 Medio", '=COUNTIF(J2:J, "Medio")', '=IF(N$7>0, N5/N$7, 0)'],
    ["🟢 Bajo", '=COUNTIF(J2:J, "Bajo")', '=IF(N$7>0, N6/N$7, 0)'],
    ["Total General", '=SUM(N4:N6)', '="IED: " & TEXT(IF(N7>0, (N4+N5)/N7, 0), "0.00%")']
  ];

  let filaInicio = 2, colInicio = 13;
  let rangoTabla = sheet.getRange(filaInicio, colInicio, resumenMatriz.length, 3);
  rangoTabla.setValues(resumenMatriz);

  let rangoTitulo = sheet.getRange(filaInicio, colInicio, 1, 3);
  rangoTitulo.merge().setBackground("#1a365d").setFontColor("#ffffff").setFontWeight("bold").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.setRowHeight(filaInicio, 30);

  let rangoHeaders = sheet.getRange(filaInicio + 1, colInicio, 1, 3);
  rangoHeaders.setBackground("#2b6cb0").setFontColor("#ffffff").setFontWeight("bold").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.setRowHeight(filaInicio + 1, 24);

  sheet.getRange(filaInicio + 2, colInicio, 3, 1).setFontWeight("bold").setHorizontalAlignment("left"); 
  sheet.getRange(filaInicio + 2, colInicio + 1, 4, 1).setHorizontalAlignment("center").setFontWeight("bold"); 
  sheet.getRange(filaInicio + 2, colInicio + 2, 3, 1).setHorizontalAlignment("center").setNumberFormat("0.00%");

  let filaTotalNum = filaInicio + resumenMatriz.length - 1;
  sheet.getRange(filaTotalNum, colInicio, 1, 3).setBackground("#edf2f7").setFontWeight("bold");
  sheet.getRange(filaTotalNum, colInicio + 1).setFontColor("#2b6cb0"); 
  sheet.getRange(filaTotalNum, colInicio + 2).setFontColor("#e53e3e").setHorizontalAlignment("center");
  sheet.setRowHeight(filaTotalNum, 26);

  rangoTabla.setBorder(true, true, true, true, true, true, "#cbd5e0", SpreadsheetApp.BorderStyle.SOLID);
  sheet.setColumnWidth(13, 140); 
  sheet.setColumnWidth(14, 160); 
  sheet.setColumnWidth(15, 160); 
}