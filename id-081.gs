/**
 * Estrategia para auditar si se requiere autenticación para remitentes aprobados.
 * ID-081: Requerir autenticación para remitentes aprobados.
 */
class GmailRequireAuthApprovedSendersStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-081", 
        valueKey: "valorPrincipal",
        noteKey: "comentario081",
        riskKey: "riesgo081",
        scoreKey: "score081"
      }
    ];
    super("Gmail Require Auth for Approved Senders Audit", configIDs);
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
    let isAuthRequired = false;
    let dataSource = "Memory";
    let rawData = null;

    if (spamPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(spamPolicies, spamPolicies[0].setting.type);
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-081] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-081] valueNode: ${JSON.stringify(valueNode)}`);
        if (valueNode.requireSenderAuthenticationForApprovedSenders === true || valueNode.require_sender_authentication === true) {
          isAuthRequired = true;
        }
      }
    } else {
      Logger.log(`[LOG] Require Auth Approved Senders no encontrado en v1, intentando Fase 2 (Admin Reports)...`);
      const logResult = this.checkAdminReportsForSetting("Require sender authentication");
      if (logResult.found) {
        isAuthRequired = logResult.enabled === true || (logResult.newValue && logResult.newValue.toLowerCase() === "true");
        dataSource = "AdminReports";
        rawData = logResult.raw;
      } else {
        // Por defecto, habilitado si se siguen las recomendaciones, pero lo asumo deshabilitado si no hay pruebas para destacar el riesgo.
        isAuthRequired = false;
        dataSource = "Default (No expuesto/Sin Logs)";
      }
    }

    let respuestaConcreta, riesgo081, comentario081;

    if (isAuthRequired) {
      respuestaConcreta = "Habilitado";
      riesgo081 = "Bajo";
      comentario081 = `La organización requiere autenticación (SPF/DKIM) para los remitentes aprobados (Fuente: ${dataSource}). Esto previene la falsificación (spoofing) de dominios de confianza que están explícitamente permitidos (whitelisted) en el filtro antispam.`;
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo081 = "Alto";
      comentario081 = `No se requiere autenticación para remitentes aprobados (Fuente: ${dataSource}). Si un atacante falsifica (spoofing) la dirección de correo de un dominio que está en la lista de permitidos, el mensaje evadirá los controles de spam por completo, facilitando ataques de phishing dirigidos altamente efectivos.`;
    }

    Logger.log(`[LOG] Require Auth Approved Senders Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo081}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario081: comentario081,
      riesgo081: riesgo081,
      score081: this.calcularScoreDeRiesgo(riesgo081)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo081: "Medio", score081: 2, comentario081: msg };
  }
}
