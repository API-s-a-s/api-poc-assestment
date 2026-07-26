/**
 * Estrategia para auditar si se omiten filtros de spam para remitentes internos.
 * ID-080: Omitir filtros de spam para mensajes recibidos de remitentes internos.
 */
class GmailBypassInternalSpamStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-080", 
        valueKey: "valorPrincipal",
        noteKey: "comentario080",
        riskKey: "riesgo080",
        scoreKey: "score080"
      }
    ];
    super("Gmail Bypass Internal Spam Audit", configIDs);
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
      Logger.log(`[DEBUG ID-080] Iniciando checkAdminReportsForSetting para: ${settingName}. Buscando desde: ${sixMonthsAgo.toISOString()}`);
      
      const response = AdminReports.Activities.list("all", "admin", {
        eventName: "CHANGE_GMAIL_SETTING",
        startTime: sixMonthsAgo.toISOString(),
        maxResults: 50
      });
      
      Logger.log(`[DEBUG ID-080] Respuesta de AdminReports obtenida. Items: ${response.items ? response.items.length : 0}`);
      
      if (response.items && response.items.length > 0) {
        for (const item of response.items) {
          for (const event of item.events) {
            if (event.name === "CHANGE_GMAIL_SETTING") {
              const paramName = event.parameters.find(p => p.name === "SETTING_NAME");
              const paramEnabled = event.parameters.find(p => p.name === "SETTING_ENABLED");
              const paramNewValue = event.parameters.find(p => p.name === "NEW_VALUE");
              
              if (paramName && paramName.value && paramName.value.toLowerCase().includes(settingName.toLowerCase())) {
                Logger.log(`[DEBUG ID-080] Coincidencia encontrada en AdminReports. Parámetros: SETTING_NAME=${paramName.value}, ENABLED=${paramEnabled ? paramEnabled.boolValue : 'N/A'}, NEW_VALUE=${paramNewValue ? paramNewValue.value : 'N/A'}`);
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
      Logger.log(`[DEBUG ID-080] No se encontraron configuraciones en AdminReports para: ${settingName}`);
      return { found: false };
    } catch (e) {
      Logger.log(`[WARN] Reports API fallback failed: ${e.message}`);
      return { found: false, error: e.message };
    }
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    Logger.log(`[DEBUG ID-080] Iniciando evaluateInMemory. Total políticas recibidas: ${policies.length}`);
    const spamPolicies = policies.filter(p => p.setting && (p.setting.type || "").includes("spam"));
    Logger.log(`[DEBUG ID-080] Políticas de Gmail Spam filtradas: ${spamPolicies.length}`);
    
    let isBypassEnabled = false;
    let dataSource = "Memory";
    let rawData = null;

    if (spamPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(spamPolicies, spamPolicies[0].setting.type);
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-080] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-080] valueNode: ${JSON.stringify(valueNode)}`);
        
        if (valueNode.bypassInternalSpam === true || 
            valueNode.bypass_internal_spam === true || 
            valueNode.bypassInternalSenders === true) {
          isBypassEnabled = true;
        } else if (Array.isArray(valueNode.spamOverride)) {
          isBypassEnabled = valueNode.spamOverride.some(rule => rule.bypassInternalSenders === true);
        }
      }
    } else {
      Logger.log(`[LOG] Bypass Internal Spam no encontrado en v1, intentando Fase 2 (Admin Reports)...`);
      const logResult = this.checkAdminReportsForSetting("Bypass spam filters for messages received from internal senders");
      if (logResult.found) {
        isBypassEnabled = logResult.enabled === true || (logResult.newValue && logResult.newValue.toLowerCase() === "true");
        dataSource = "AdminReports";
        rawData = logResult.raw;
      } else {
        // Por defecto, esta configuración suele estar deshabilitada si no se toca
        isBypassEnabled = false;
        dataSource = "Default (No expuesto/Sin Logs)";
      }
    }

    let respuestaConcreta, riesgo080, comentario080;

    if (isBypassEnabled) {
      respuestaConcreta = "Habilitado";
      riesgo080 = "Alto";
      comentario080 = `Se omiten los filtros de spam para remitentes internos Fuente: ${dataSource}.`;
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo080 = "Bajo";
      comentario080 = `No se omiten los filtros de spam para remitentes internos. Fuente: ${dataSource}.`;
    }

    Logger.log(`[LOG] Bypass Internal Spam Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo080} | Fuente: ${dataSource}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario080: comentario080,
      riesgo080: riesgo080,
      score080: this.calcularScoreDeRiesgo(riesgo080)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo080: "Medio", score080: 2, comentario080: msg };
  }
}
