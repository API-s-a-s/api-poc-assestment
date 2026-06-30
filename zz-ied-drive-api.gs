/**
 * Auditoría Avanzada de Seguridad en Google Workspace (Índice de Exposición de Datos - IED)
 * VERSIÓN DRIVE API v3 - ESQUEMA PLANO DE 10 COLUMNAS CON TABLA RESUMEN EN COLUMNA M (MÉTRICAS IED)
 */

function AuditoriaIEDrivePersonal() {
  const MAX_EXEC_TIME_MS = 4.5 * 60 * 1000; 
  Logger.log("=== INICIANDO AUDITORÍA IED (DRIVE API v3) ===");
  let ui = null;
  
  try {
    ui = SpreadsheetApp.getUi();
  } catch (e) {
    // Activador por tiempo
  }

  const scriptProperties = PropertiesService.getScriptProperties();
  let isFinished = scriptProperties.getProperty('isFinished');
  let pageToken = scriptProperties.getProperty('pageToken') || null;

  if (isFinished === 'true') {
    if (ui) ui.alert("✅ El Índice de Exposición de Datos histórico ya está completo y actualizado.");
    scriptProperties.deleteAllProperties();
    return;
  }

  // Si es el inicio absoluto del escaneo, preparamos y limpiamos la hoja con sus 10 columnas
  if (!pageToken) {
    inicializarHojaIED();
  }

  const startTime = Date.now(); 
  
  while (Date.now() - startTime < MAX_EXEC_TIME_MS) { 
    // Máscara de campos optimizada incluyendo modifiedTime
    let optionalArgs = {
      q: "'me' in owners and trashed=false", 
      fields: "nextPageToken, files(id, name, mimeType, modifiedTime, owners, permissions(id, type, role, emailAddress, domain, allowFileDiscovery))", 
      pageSize: 1000 
    };
    
    if (pageToken) optionalArgs.pageToken = pageToken;

    // Ejecución robusta protegida con paciente retroceso exponencial ante cuotas
    let response = ejecutarDriveAPIConBackoff(optionalArgs);
    
    if (!response) {
      Logger.log("[ERROR CRÍTICO] La red rechazó múltiples reintentos. Deteniendo ejecución."); 
      isFinished = 'error';
      break;
    }

    let files = response.files || [];
    if (files.length > 0) {
      Logger.log(`[PROCESANDO] ${files.length} archivos obtenidos en esta página...`);
      let procesados = procesarArchivosDriveV3(files);
      
      // Escribimos en la hoja inmediatamente, bloque a bloque.
      if (procesados.length > 0) {
        escribirEnHojaActiva(procesados);
        SpreadsheetApp.flush(); // Forzamos a Google a actualizar la pantalla para ver los datos en vivo.
      }
    }

    pageToken = response.nextPageToken; 
    if (!pageToken) {
      Logger.log(`[INFO] Se ha escaneado la totalidad del Drive.`);
      isFinished = 'true';
      break;
    }
  }

  // ===============================================
  // LÓGICA DE PERSISTENCIA Y CONTINUIDAD ASÍNCRONA
  // ===============================================
  if (isFinished === 'true') {
    scriptProperties.deleteAllProperties();
    Logger.log("=== AUDITORÍA IED COMPLETADA CON ÉXITO ===");
    
    // Invocación de la tabla resumen una vez consolidada toda la data
    crearTablaResumenM();
    
    if (ui) ui.alert("✅ Índice de Exposición de Datos de Drive completado con éxito.");
  } else if (isFinished === 'error') {
    scriptProperties.deleteAllProperties();
  } else {
    // Si se acabó el tiempo, serializamos el estado y programamos la resurrección
    if (pageToken) scriptProperties.setProperty('pageToken', pageToken);
    
    let triggers = ScriptApp.getProjectTriggers();
    triggers.forEach(trigger => {
      if(trigger.getHandlerFunction() === 'iniciarAuditoriaIED') ScriptApp.deleteTrigger(trigger);
    });

    ScriptApp.newTrigger('iniciarAuditoriaIED') 
             .timeBased()
             .after(1 * 60 * 1000) 
             .create();
  }
}

// ==========================================
// FUNCIÓN DE PREPARACIÓN DE PESTAÑA (10 COLUMNAS)
// ==========================================
function inicializarHojaIED() {
  const SHEET_NAME = "Auditoria IED personal";
  let ss = SpreadsheetApp.getActiveSpreadsheet();
  if (!ss) return;
  let sheet = ss.getSheetByName(SHEET_NAME);
  
  if (sheet) {
    sheet.clear(); 
    Logger.log(`[LIMPIEZA] Contenido y formatos previos de la pestaña '${SHEET_NAME}' eliminados.`);
  } else {
    sheet = ss.insertSheet(SHEET_NAME);
    Logger.log(`[CREACIÓN] Pestaña '${SHEET_NAME}' creada.`);
  }
  
  // Imprimir exactamente las 10 columnas requeridas por el marco forense
  sheet.appendRow([
    "Fecha", 
    "Actor", 
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
// NUEVA FUNCIÓN: CONSTRUCCIÓN DE TABLA RESUMEN EN COLUMNA M CON IED
// ==========================================
function crearTablaResumenM() {
  const SHEET_NAME = "Auditoria IED personal";
  let ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(SHEET_NAME);
  if (!sheet) return;

  Logger.log("[RESUMEN] Iniciando la inyección de la tabla de control (Métricas de Porcentaje e IED)...");

  // Estructura bidimensional de datos y reglas lógicas mapeadas con Porcentajes
  let resumenMatriz = [
    ["Resumen de Reglas e Índice de Exposición", "", ""],
    ["Criterio de Riesgo", "Cantidad de Archivos", "Porcentaje (%)"],
    ["🔴 Alto", '=COUNTIF(J2:J, "Alto")', '=IF(N$7>0, N4/N$7, 0)'],
    ["🟡 Medio", '=COUNTIF(J2:J, "Medio")', '=IF(N$7>0, N5/N$7, 0)'],
    ["🟢 Bajo", '=COUNTIF(J2:J, "Bajo")', '=IF(N$7>0, N6/N$7, 0)'],
    ["Total General", '=SUM(N4:N6)', '="IED: " & TEXT(IF(N7>0, (N4+N5)/N7, 0), "0.00%")']
  ];

  // Ubicación geométrica: Fila 2, Columna 13 (M)
  let filaInicio = 2;
  let colInicio = 13;
  
  let rangoTabla = sheet.getRange(filaInicio, colInicio, resumenMatriz.length, 3);
  rangoTabla.setValues(resumenMatriz);

  // --- ESTILIZADO DE DISEÑO PROFESIONAL DE LA TABLA ---
  
  // 1. Fila de Título Unificada
  let rangoTitulo = sheet.getRange(filaInicio, colInicio, 1, 3);
  rangoTitulo.merge();
  rangoTitulo.setBackground("#1a365d") // Azul oscuro ejecutivo
             .setFontColor("#ffffff")
             .setFontWeight("bold")
             .setHorizontalAlignment("center")
             .setVerticalAlignment("middle");
  sheet.setRowHeight(filaInicio, 30);

  // 2. Fila de Encabezados de Métricas
  let rangoHeaders = sheet.getRange(filaInicio + 1, colInicio, 1, 3);
  rangoHeaders.setBackground("#2b6cb0") // Azul cobalto corporativo
              .setFontColor("#ffffff")
              .setFontWeight("bold")
              .setHorizontalAlignment("center")
              .setVerticalAlignment("middle");
  sheet.setRowHeight(filaInicio + 1, 24);

  // 3. Ajustes de Alineación y Formato en Filas Internas
  sheet.getRange(filaInicio + 2, colInicio, 3, 1).setFontWeight("bold").setHorizontalAlignment("left"); // Criterios
  sheet.getRange(filaInicio + 2, colInicio + 1, 4, 1).setHorizontalAlignment("center").setFontWeight("bold"); // Cantidades por Fórmula
  
  // Dar formato de porcentaje a las columnas de "Alto", "Medio", "Bajo" (Filas 4, 5 y 6)
  sheet.getRange(filaInicio + 2, colInicio + 2, 3, 1).setHorizontalAlignment("center").setNumberFormat("0.00%");

  // 4. Fila de Consolidación Total e Índice de Exposición (IED)
  let filaTotalNum = filaInicio + resumenMatriz.length - 1;
  sheet.getRange(filaTotalNum, colInicio, 1, 3).setBackground("#edf2f7").setFontWeight("bold");
  sheet.getRange(filaTotalNum, colInicio + 1).setFontColor("#2b6cb0"); 
  sheet.getRange(filaTotalNum, colInicio + 2).setFontColor("#e53e3e").setHorizontalAlignment("center"); // IED en color rojo/alerta
  sheet.setRowHeight(filaTotalNum, 26);

  // 5. Aplicación de Bordes Suaves
  rangoTabla.setBorder(true, true, true, true, true, true, "#cbd5e0", SpreadsheetApp.BorderStyle.SOLID);

  // 6. Dimensionamiento Óptimo de Ancho de Columnas (M, N, O)
  sheet.setColumnWidth(13, 140); // Columna M: Criterio de Riesgo
  sheet.setColumnWidth(14, 160); // Columna N: Cantidad de Archivos
  sheet.setColumnWidth(15, 160); // Columna O: Porcentaje e IED
  
  Logger.log("[RESUMEN] Tabla resumen con porcentajes e IED renderizada con éxito.");
}

// ==========================================
// PATRÓN DE DISEÑO: RETROCESO EXPONENCIAL TRUNCADO
// ==========================================
function ejecutarDriveAPIConBackoff(optionalArgs) {
  let intentos = 0;
  let maxIntentos = 6; 
  
  while (intentos < maxIntentos) {
    try {
      return Drive.Files.list(optionalArgs); 
    } catch (e) {
      let errorMsg = e.message.toLowerCase();
      if (errorMsg.includes('403') || errorMsg.includes('429') || errorMsg.includes('rate limit') || errorMsg.includes('too many')) {
        let pausa = Math.pow(2, intentos) * 1000 + (Math.random() * 1000); 
        Logger.log(`[API LIMIT] Cuota excedida. Hibernando por ${Math.round(pausa)}ms (Intento ${intentos + 1})`);
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

function procesarArchivosDriveV3(files) {
  const auth = new AuthService();
  const CORPORATE_DOMAIN = auth.getDomain();
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

      // Iteración profunda sobre la lista de control de acceso (ACLs) vigente
      permissions.forEach(perm => {
        if (perm.role === 'owner') return; 

        if (perm.type === 'anyone') {
          anyoneFlag = true; 
          destinatariosSet.add("Cualquiera (Anyone)"); 
          if (perm.allowFileDiscovery) {
            publicOnWebFlag = true; 
          }
        } else if (perm.type === 'user' || perm.type === 'group') {
          let email = perm.emailAddress || "";
          let domain = perm.domain || "";
          
          if (email) destinatariosSet.add(email);

          // Escrutinio de dominios cruzados
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
        destinatarios.push("Toda la organización (Vía Enlace)");
      }

      if (destinatarios.length === 0 && !anyoneFlag && !domainFlag) return; 

      let visibilidad = "Private";
      if (anyoneFlag && publicOnWebFlag) visibilidad = "public_on_the_web"; 
      else if (anyoneFlag) visibilidad = "people_with_link"; 
      else if (domainFlag && !compartidoExternoFlag) visibilidad = "people_within_domain_with_link"; 
      else if (domainFlag || compartidoExternoFlag) visibilidad = "externally";
      else if (destinatarios.length > 0) visibilidad = "shared_internally"; 

      let strCualquiera = anyoneFlag ? "Sí" : "No";
      let strExterno = compartidoExternoFlag ? "Sí" : "No";

      let riesgo = "Bajo";
      if (anyoneFlag) {
        riesgo = "Alto"; 
      } else if (compartidoExternoFlag) {
        riesgo = "Medio"; 
      } else {
        riesgo = "Bajo"; 
      }

      let fechaModificacion = "N/A";
      if (file.modifiedTime) {
        fechaModificacion = Utilities.formatDate(new Date(file.modifiedTime), "America/Bogota", "yyyy-MM-dd HH:mm:ss");
      }

      filas.push([
        fechaModificacion,       // 1. Fecha de última modificación
        actorEmail,              // 2. Actor (Propietario)
        "Google Drive",          // 3. Aplicación
        file.id,                 // 4. ID Documento
        file.name,               // 5. Titulo del recurso
        visibilidad,             // 6. Visibilidad/Severidad
        destinatarios.join(', '),// 7. Destinatario(s) limpios y consolidados
        strExterno,              // 8. Compartido con Externo
        strCualquiera,           // 9. Cualquiera con el Enlace
        riesgo                   // 10. Criterio de Riesgo
      ]);

    } catch (e) {
      Logger.log(`[ERROR EN ARCHIVO] ${e.message}`);
    }
  });

  return filas;
}

function escribirEnHojaActiva(matrizDatos) {
  const SHEET_NAME = "Auditoria IED personal";
  let ss = SpreadsheetApp.getActiveSpreadsheet();
  if (!ss) return;
  let sheet = ss.getSheetByName(SHEET_NAME);
  if (!sheet) return; 
  
  let ultimaFila = Math.max(sheet.getLastRow(), 1); 
  try {
    sheet.getRange(ultimaFila + 1, 1, matrizDatos.length, matrizDatos[0].length).setValues(matrizDatos);
    Logger.log(`[ESCRITURA CHUNK] Pegadas ${matrizDatos.length} filas desde la posición ${ultimaFila + 1}`);
  } catch (e) {
    Logger.log(`[ERROR DE ESCRITURA]: ${e.message}`);
  }
}