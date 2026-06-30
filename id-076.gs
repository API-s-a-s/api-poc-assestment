/**
 * Estrategia para auditar la configuración del Sandbox de seguridad en Gmail.
 * ID-076: Sandbox de seguridad (Security Sandbox).
 */
class GmailSecuritySandboxStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-076", 
        valueKey: "valorPrincipal",
        noteKey: "comentario076",
        riskKey: "riesgo076",
        scoreKey: "score076"
      }
    ];
    super("Gmail Security Sandbox Audit", configIDs);
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

    const sandboxPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.security_sandbox"));
    let isSandboxEnabled = false;
    let dataSource = "Memory";
    let rawData = null;

    if (sandboxPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(sandboxPolicies, "gmail.security_sandbox");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-076] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-076] valueNode: ${JSON.stringify(valueNode)}`);
        if (valueNode.enableSecuritySandbox === true || valueNode.state === 'ENABLED') {
          isSandboxEnabled = true;
        }
      }
    } else {
      Logger.log(`[LOG] Security Sandbox no encontrado en v1, intentando Fase 2 (Admin Reports)...`);
      const logResult = this.checkAdminReportsForSetting("Sandbox");
      if (logResult.found) {
        isSandboxEnabled = logResult.enabled === true || (logResult.newValue && logResult.newValue.toLowerCase() === "true");
        dataSource = "AdminReports";
        rawData = logResult.raw;
      } else {
        // Asumimos deshabilitado por defecto si no hay reportes (no viene habilitado en tenants básicos)
        isSandboxEnabled = false;
        dataSource = "Default (No expuesto/Sin Logs)";
      }
    }

    let respuestaConcreta, riesgo076, comentario076;

    if (isSandboxEnabled) {
      respuestaConcreta = "Habilitado";
      riesgo076 = "Bajo";
      comentario076 = `El Sandbox de seguridad para correo se encuentra habilitado (Fuente: ${dataSource}). Los archivos adjuntos sospechosos se analizan en un entorno virtual aislado para detectar ransomware y malware de día cero de forma heurística antes de entregarse.`;
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo076 = "Alto";
      comentario076 = `El Sandbox de seguridad de Gmail está deshabilitado (Fuente: ${dataSource}). Los usuarios están expuestos a ataques de malware de día cero (Zero-Day) o ransomware empaquetado en adjuntos, ya que estos no son detonados en un entorno aislado (sandbox) antes de llegar al buzón.`;
    }

    Logger.log(`[LOG] Security Sandbox Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo076}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario076: comentario076,
      riesgo076: riesgo076,
      score076: this.calcularScoreDeRiesgo(riesgo076)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo076: "Medio", score076: 2, comentario076: msg };
  }
}
