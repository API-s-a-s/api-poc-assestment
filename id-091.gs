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
      return { found: false, error: e.message };
    }
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    const relayPolicies = policies.filter(p => p.setting && ((p.setting.type || "").endsWith("gmail.smtp_relay") || (p.setting.type || "").endsWith("gmail.smtp_relay_service")));
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
        const rules = valueNode.rules || valueNode.settingRules || [];
        rulesCount = rules.length;
      }
    } else {
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
      comentario091 = `Se encontraron ${rulesCount} configuraciones de Servicio de Retransmisión SMTP (SMTP Relay) (Fuente: ${dataSource}). Esto permite que sistemas on-premise, escáneres o aplicaciones de terceros envíen correos hacia el exterior aparentando provenir del dominio de Workspace. Es imperativo revisar periódicamente que las IPs autorizadas estén estrictamente delimitadas para evitar que el dominio sea utilizado para relay abierto de spam.`;
    } else {
      riesgo091 = "Bajo";
      comentario091 = `No existen configuraciones del Servicio de Retransmisión SMTP (SMTP Relay) (Fuente: ${dataSource}). Ninguna IP o aplicación externa tiene permisos a nivel de ruteo para retransmitir correo a través de los servidores SMTP de Google para este dominio.`;
    }

    Logger.log(`[LOG] SMTP Relay Audit: ${rulesCount} configuraciones detectadas. | Riesgo: ${riesgo091}`);

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
