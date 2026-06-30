/**
 * Estrategia para auditar la configuración de S/MIME en Gmail.
 * ID-061: S/MIME para el cifrado a nivel de mensaje.
 */
class GmailSmimeEncryptionStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-061", 
        valueKey: "valorPrincipal",
        noteKey: "comentario061",
        riskKey: "riesgo061",
        scoreKey: "score061"
      }
    ];
    super("Gmail S/MIME Encryption Audit", configIDs);
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

    // Fase 1: Intentar buscar en las políticas globales en memoria
    Logger.log(`[DEBUG ID-061] Evaluando política S/MIME. Políticas recibidas: ${policies ? policies.length : 0}`);
    const smimePolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.smime_encryption"));
    Logger.log(`[DEBUG ID-061] Políticas S/MIME filtradas encontradas: ${smimePolicies.length}`);
    let isSmimeEnabled = false;
    let dataSource = "Memory";
    let rawData = null;

    if (smimePolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(smimePolicies, "gmail.smime_encryption");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-061] Política raíz efectiva encontrada: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const setting = rootPolicy.setting;
        const valueNode = setting.value || setting;
        Logger.log(`[DEBUG ID-061] valueNode extraído: ${JSON.stringify(valueNode)}`);
        if (valueNode.enableSmimeEncryption === true || valueNode.enableSmimeEncryption === 'STATUS_ENABLED') {
          isSmimeEnabled = true;
          Logger.log(`[DEBUG ID-061] ¡isSmimeEnabled seteado a TRUE!`);
        } else {
          Logger.log(`[DEBUG ID-061] valueNode.enableSmimeEncryption no indica habilitado. Es: ${valueNode.enableSmimeEncryption}`);
        }
      } else {
        Logger.log(`[DEBUG ID-061] rootPolicy.setting es nulo o indefinido.`);
      }
    } else {
      // Fase 2: Si no existe en la API global, buscar en los logs de auditoría como Fallback
      Logger.log(`[LOG] S/MIME no encontrado en v1, intentando Fase 2 (Admin Reports)...`);
      const logResult = this.checkAdminReportsForSetting("S/MIME");
      if (logResult.found) {
        isSmimeEnabled = logResult.enabled === true || (logResult.newValue && logResult.newValue.toLowerCase() === "true");
        dataSource = "AdminReports";
        rawData = logResult.raw;
      } else {
        // Si no se encuentra en logs, asumimos el valor predeterminado (Deshabilitado)
        isSmimeEnabled = false;
        dataSource = "Default (No expuesto/Sin Logs)";
      }
    }

    let respuestaConcreta, riesgo061, comentario061;

    if (isSmimeEnabled) {
      respuestaConcreta = "Habilitado";
      riesgo061 = "Bajo";
      comentario061 = `El cifrado a nivel de mensaje mediante S/MIME se encuentra habilitado (Fuente: ${dataSource}). Esto asegura el cifrado de extremo a extremo basado en certificados, garantizando alta confidencialidad para comunicaciones críticas.`;
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo061 = "Medio"; // Usualmente Medio ya que TLS oportunista suele estar, pero para entornos Enterprise sin S/MIME es un hallazgo.
      comentario061 = `El cifrado S/MIME a nivel de mensaje se encuentra deshabilitado (Fuente: ${dataSource}). Aunque el correo usa cifrado en tránsito (TLS), la organización carece de cifrado de extremo a extremo, dejando el contenido de los mensajes expuesto si los servidores intermediarios son comprometidos.`;
    }

    Logger.log(`[LOG] S/MIME Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo061}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario061: comentario061,
      riesgo061: riesgo061,
      score061: this.calcularScoreDeRiesgo(riesgo061)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo061: "Medio", score061: 2, comentario061: msg };
  }
}
