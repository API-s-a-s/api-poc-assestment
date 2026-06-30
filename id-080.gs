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

    const spamPolicies = policies.filter(p => p.setting && ((p.setting.type || "").endsWith("gmail.spam") || (p.setting.type || "").endsWith("gmail.spam_settings")));
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
        if (valueNode.bypassInternalSpam === true || valueNode.bypass_internal_spam === true) {
          isBypassEnabled = true;
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
      comentario080 = `Se omiten los filtros de spam para remitentes internos (Fuente: ${dataSource}). Esta configuración representa un riesgo crítico, ya que si una cuenta interna es comprometida (Account Takeover), los atacantes podrán propagar phishing interno o malware a toda la organización sin ninguna restricción de los motores antispam.`;
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo080 = "Bajo";
      comentario080 = `No se omiten los filtros de spam para remitentes internos (Fuente: ${dataSource}). Todo el correo, incluso si proviene de dominios internos, es inspeccionado. Esto es una buena práctica para contener el riesgo de movimiento lateral mediante correos internos comprometidos.`;
    }

    Logger.log(`[LOG] Bypass Internal Spam Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo080}`);

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
