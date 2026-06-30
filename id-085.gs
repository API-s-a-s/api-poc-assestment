/**
 * Estrategia para auditar si OCR está habilitado en los archivos adjuntos.
 * ID-085: Habilitar OCR para archivos adjuntos de correo electrónico.
 */
class GmailOcrAttachmentsStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-085", 
        valueKey: "valorPrincipal",
        noteKey: "comentario085",
        riskKey: "riesgo085",
        scoreKey: "score085"
      }
    ];
    super("Gmail OCR Attachments Audit", configIDs);
    this.category = "Email y DNS";
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  checkAdminReportsForSetting(settingName) {
    try {
      const sixMonthsAgo = new Date();
      sixMonthsAgo.setDate(sixMonthsAgo.getDate() - 180);
      
      const response = AdminReports.Activities.list("all", "admin", {
        eventName: "CHANGE_GMAIL_SETTING",
        startTime: sixMonthsAgo.toISOString(),
        maxResults: 50
      });
      
      if (response.items && response.items.length > 0) {
        for (const item of response.items) {
          for (const event of item.events) {
            if (event.name === "CHANGE_GMAIL_SETTING") {
              const paramName = event.parameters.find(p => p.name === "SETTING_NAME");
              const paramEnabled = event.parameters.find(p => p.name === "SETTING_ENABLED");
              const paramNewValue = event.parameters.find(p => p.name === "NEW_VALUE");
              
              if (paramName && paramName.value && paramName.value.toLowerCase().includes(settingName.toLowerCase())) {
                return {
                  found: true,
                  enabled: paramEnabled ? paramEnabled.boolValue : null,
                  newValue: paramNewValue ? paramNewValue.value : null,
                  raw: item
                };
              }
            }
          }
        }
      }
      return { found: false };
    } catch (e) {
      Logger.log(`[WARN] Reports API fallback failed: ${e.message}`);
      return { found: false, error: e.message };
    }
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    const ocrPolicies = policies.filter(p => p.setting && ((p.setting.type || "").endsWith("gmail.ocr_attachments") || (p.setting.type || "").endsWith("gmail.ocr") || (p.setting.type || "").endsWith("gmail.attachment_compliance")));
    let isOcrEnabled = false;
    let dataSource = "Memory";
    let rawData = null;

    if (ocrPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(ocrPolicies, ocrPolicies[0].setting.type);
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-085] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-085] valueNode: ${JSON.stringify(valueNode)}`);
        if (valueNode.enableOcr === true || valueNode.state === 'ENABLED' || valueNode.ocrEnabled === true) {
          isOcrEnabled = true;
        }
      }
    } else {
      Logger.log(`[LOG] OCR Attachments no encontrado en v1, intentando Fase 2 (Admin Reports)...`);
      const logResult = this.checkAdminReportsForSetting("OCR");
      if (logResult.found) {
        isOcrEnabled = logResult.enabled === true || (logResult.newValue && logResult.newValue.toLowerCase() === "true");
        dataSource = "AdminReports";
        rawData = logResult.raw;
      } else {
        // Por defecto no suele estar activado a nivel tenant completo
        isOcrEnabled = false;
        dataSource = "Default (No expuesto/Sin Logs)";
      }
    }

    let respuestaConcreta, riesgo085, comentario085;

    if (isOcrEnabled) {
      respuestaConcreta = "Habilitado";
      riesgo085 = "Bajo";
      comentario085 = `El escaneo OCR para archivos adjuntos se encuentra habilitado (Fuente: ${dataSource}). Las imágenes y PDFs escaneados dentro del correo son procesados y su texto es inspeccionado por las reglas de cumplimiento (DLP), lo que previene la exfiltración de información sensible (como tarjetas de crédito o credenciales) escondida en formatos de imagen.`;
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo085 = "Medio";
      comentario085 = `El reconocimiento óptico de caracteres (OCR) para adjuntos está deshabilitado (Fuente: ${dataSource}). Los datos sensibles incrustados en imágenes (fotos de tarjetas, capturas de pantalla de bases de datos) pueden evadir los controles DLP y abandonar la organización sin generar alertas.`;
    }

    Logger.log(`[LOG] OCR Attachments Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo085}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario085: comentario085,
      riesgo085: riesgo085,
      score085: this.calcularScoreDeRiesgo(riesgo085)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo085: "Medio", score085: 2, comentario085: msg };
  }
}
