/**
 * Estrategia para auditar configuraciones del servicio de retransmisión SMTP.
 * ID-091: Configuraciones de servicio de retransmisión SMTP.
 */
class GmailSmtpRelayStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-091", 
        valueKey: "valorPrincipal",
        noteKey: "comentario091",
        riskKey: "riesgo091",
        scoreKey: "score091"
      }
    ];
    super("Gmail SMTP Relay Audit", configIDs);
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
      Logger.log(`[DEBUG ID-091] Iniciando checkAdminReportsForSetting para: ${settingName}. Buscando desde: ${sixMonthsAgo.toISOString()}`);
      
      const response = AdminReports.Activities.list("all", "admin", {
        eventName: "CHANGE_GMAIL_SETTING",
        startTime: sixMonthsAgo.toISOString(),
        maxResults: 50
      });
      
      Logger.log(`[DEBUG ID-091] Respuesta de AdminReports obtenida. Items: ${response.items ? response.items.length : 0}`);
      
      if (response.items && response.items.length > 0) {
        for (const item of response.items) {
          for (const event of item.events) {
            if (event.name === "CHANGE_GMAIL_SETTING") {
              const paramName = event.parameters.find(p => p.name === "SETTING_NAME");
              const paramEnabled = event.parameters.find(p => p.name === "SETTING_ENABLED");
              const paramNewValue = event.parameters.find(p => p.name === "NEW_VALUE");
              
              if (paramName && paramName.value && paramName.value.toLowerCase().includes(settingName.toLowerCase())) {
                Logger.log(`[DEBUG ID-091] Coincidencia encontrada en AdminReports. Parámetros: SETTING_NAME=${paramName.value}, ENABLED=${paramEnabled ? paramEnabled.boolValue : 'N/A'}, NEW_VALUE=${paramNewValue ? paramNewValue.value : 'N/A'}`);
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
      Logger.log(`[DEBUG ID-091] No se encontraron configuraciones en AdminReports para: ${settingName}`);
      return { found: false };
    } catch (e) {
      Logger.log(`[WARN] Reports API fallback failed: ${e.message}`);
      return { found: false, error: e.message };
    }
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    Logger.log(`[DEBUG ID-091] Iniciando evaluateInMemory. Total políticas recibidas: ${policies.length}`);
    const relayPolicies = policies.filter(p => p.setting && ((p.setting.type || "").includes("smtp_relay") || (p.setting.type || "").includes("relay")));
    Logger.log(`[DEBUG ID-091] Políticas de Gmail SMTP Relay filtradas: ${relayPolicies.length}`);

    let rulesCount = 0;
    let dataSource = "Memory";
    let rawData = null;

    if (relayPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(relayPolicies, relayPolicies[0].setting.type);
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-091] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-091] valueNode: ${JSON.stringify(valueNode)}`);
        const rules = valueNode.rules || valueNode.settingRules || valueNode.relayRules || [];
        Logger.log(`[DEBUG ID-091] Reglas SMTP Relay detectadas: ${rules.length}`);
        rulesCount = rules.length;
      }
    } else {
      Logger.log(`[LOG] SMTP relay service no encontrado en v1, intentando Fase 2 (Admin Reports)...`);
      const logResult = this.checkAdminReportsForSetting("SMTP relay service");
      if (logResult.found) {
        rulesCount = (logResult.enabled === true || (logResult.newValue && logResult.newValue !== "")) ? 1 : 0;
        dataSource = "AdminReports";
        rawData = logResult.raw;
      } else {
        rulesCount = 0;
        dataSource = "Default (No expuesto/Sin Logs)";
      }
    }

    let riesgo091, comentario091;

    if (rulesCount > 0) {
      riesgo091 = "Medio"; // Requiere auditoría de IPs permitidas y métodos de autenticación
      comentario091 = `Se encontraron ${rulesCount} configuraciones SMTP Relay`;
    } else {
      riesgo091 = "Bajo";
      comentario091 = `No existen configuraciones del servicio de retransmisión SMTP.`;
    }

    Logger.log(`[LOG] SMTP Relay Audit: ${rulesCount} configuraciones detectadas. | Riesgo: ${riesgo091} | Fuente: ${dataSource}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: rulesCount,
      comentario091: comentario091,
      riesgo091: riesgo091,
      score091: this.calcularScoreDeRiesgo(riesgo091)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo091: "Medio", score091: 2, comentario091: msg };
  }
}
