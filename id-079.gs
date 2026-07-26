/**
 * Estrategia para auditar la configuración de Filtrado Agresivo de Spam.
 * ID-079: Filtrado agresivo de spam.
 */
class GmailAggressiveSpamStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-079", 
        valueKey: "valorPrincipal",
        noteKey: "comentario079",
        riskKey: "riesgo079",
        scoreKey: "score079"
      }
    ];
    super("Gmail Aggressive Spam Filter Audit", configIDs);
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
      Logger.log(`[DEBUG ID-079] Iniciando checkAdminReportsForSetting para: ${settingName}. Buscando desde: ${sixMonthsAgo.toISOString()}`);
      
      const response = AdminReports.Activities.list("all", "admin", {
        eventName: "CHANGE_GMAIL_SETTING",
        startTime: sixMonthsAgo.toISOString(),
        maxResults: 50
      });
      
      Logger.log(`[DEBUG ID-079] Respuesta de AdminReports obtenida. Items: ${response.items ? response.items.length : 0}`);
      
      if (response.items && response.items.length > 0) {
        for (const item of response.items) {
          for (const event of item.events) {
            if (event.name === "CHANGE_GMAIL_SETTING") {
              const paramName = event.parameters.find(p => p.name === "SETTING_NAME");
              const paramEnabled = event.parameters.find(p => p.name === "SETTING_ENABLED");
              const paramNewValue = event.parameters.find(p => p.name === "NEW_VALUE");
              
              if (paramName && paramName.value && paramName.value.toLowerCase().includes(settingName.toLowerCase())) {
                Logger.log(`[DEBUG ID-079] Coincidencia encontrada en AdminReports. Parámetros: SETTING_NAME=${paramName.value}, ENABLED=${paramEnabled ? paramEnabled.boolValue : 'N/A'}, NEW_VALUE=${paramNewValue ? paramNewValue.value : 'N/A'}`);
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
      Logger.log(`[DEBUG ID-079] No se encontraron configuraciones en AdminReports para: ${settingName}`);
      return { found: false };
    } catch (e) {
      Logger.log(`[WARN] Reports API fallback failed: ${e.message}`);
      return { found: false, error: e.message };
    }
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    Logger.log(`[DEBUG ID-079] Iniciando evaluateInMemory. Total políticas recibidas: ${policies.length}`);
    const spamPolicies = policies.filter(p => p.setting && (p.setting.type || "").includes("spam"));
    Logger.log(`[DEBUG ID-079] Políticas de Gmail Spam filtradas: ${spamPolicies.length}`);
    
    let isAggressiveEnabled = false;
    let dataSource = "Memory";
    let rawData = null;

    if (spamPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(spamPolicies, spamPolicies[0].setting.type);
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-079] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-079] valueNode: ${JSON.stringify(valueNode)}`);
        
        if (valueNode.enableAggressiveSpamFilter === true || 
            valueNode.aggressiveSpamFiltering === true || 
            valueNode.enableAggressiveFiltering === true) {
          isAggressiveEnabled = true;
        } else if (Array.isArray(valueNode.spamOverride)) {
          isAggressiveEnabled = valueNode.spamOverride.some(rule => rule.enableAggressiveFiltering === true);
        }
      }
    } else {
      Logger.log(`[LOG] Aggressive Spam no encontrado en v1, intentando Fase 2 (Admin Reports)...`);
      const logResult = this.checkAdminReportsForSetting("Aggressive spam");
      if (logResult.found) {
        isAggressiveEnabled = logResult.enabled === true || (logResult.newValue && logResult.newValue.toLowerCase() === "true");
        dataSource = "AdminReports";
        rawData = logResult.raw;
      } else {
        // Por defecto, el filtrado agresivo está deshabilitado (ya que causa falsos positivos)
        isAggressiveEnabled = false;
        dataSource = "Default (No expuesto/Sin Logs)";
      }
    }

    let respuestaConcreta, riesgo079, comentario079;

    if (isAggressiveEnabled) {
      // Generalmente debe estar deshabilitada a menos que sea estrictamente necesario.
      respuestaConcreta = "Habilitado";
      riesgo079 = "Medio";
      comentario079 = `El filtrado agresivo de spam se encuentra habilitado Fuente: ${dataSource}.`;
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo079 = "Bajo";
      comentario079 = `El filtrado agresivo de spam está deshabilitado. Fuente: ${dataSource}.`;
    }

    Logger.log(`[LOG] Aggressive Spam Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo079} | Fuente: ${dataSource}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario079: comentario079,
      riesgo079: riesgo079,
      score079: this.calcularScoreDeRiesgo(riesgo079)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo079: "Medio", score079: 2, comentario079: msg };
  }
}
