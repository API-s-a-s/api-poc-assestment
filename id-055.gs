/**
 * Estrategia para auditar la lista de aplicaciones permitidas del Marketplace.
 * Evalúa cuántas apps externas tienen permiso explícito de instalación.
 * Utiliza Cloud Identity API en memoria
 */
class MarketplaceAllowlistStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-055", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario055",
        riskKey: "riesgo055",
        scoreKey: "score055"
      }
    ];

    super("Marketplace Allowlist Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Integración de aplicaciones";
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;

    if (!policies) {
      return this._buildErrorResponse("Falta el contexto global.");
    }

    const targetPolicies = policies.filter(p => p.setting && p.setting.type === "workspace_marketplace.apps_allowlist");

    let allowedCount = 0;
    let dangerousCount = 0;
    let hasDangerousScopes = false;
    let appsInfoStr = "";
    let rawAppsList = [];

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "workspace_marketplace.apps_allowlist");
      if (rootPolicy && rootPolicy.setting) {
        const configNode = rootPolicy.setting.value || rootPolicy.setting;
        const allowlistNode = configNode.workspaceMarketplaceAppsAllowlist || configNode.workspace_marketplace_apps_allowlist || configNode;
        const apps = allowlistNode.apps || [];
        
        allowedCount = apps.length;
        rawAppsList = apps;
        appsInfoStr = JSON.stringify(apps).toLowerCase();

        apps.forEach(app => {
          const appStr = JSON.stringify(app).toLowerCase();
          if (appStr.includes("drive") || appStr.includes("gmail") || appStr.includes("mail.google.com")) {
             dangerousCount++;
             hasDangerousScopes = true;
          }
        });
      }
    }

    let riesgo055, comentario055;
    let rawOutput = JSON.stringify(rawAppsList);

    if (allowedCount === 0) {
      riesgo055 = "Bajo";
      rawOutput = "0%";
      comentario055 = `${dangerousCount} de ${allowedCount} apps peligrosas: No existen aplicaciones configuradas en la lista de confianza (Allowlist) de Google Workspace Marketplace.`;
    } else {
      if (hasDangerousScopes) {
        riesgo055 = "Alto";
        comentario055 = `${dangerousCount} de ${allowedCount} apps peligrosas: ATENCIÓN: Se detectaron identificadores asociados a permisos de alto riesgo (Drive y/o Gmail) autorizados en esta lista.`;
      } else {
        riesgo055 = "Medio";
        comentario055 = `${dangerousCount} de ${allowedCount} apps peligrosas: Hay aplicaciones de terceros explícitamente permitidas (Allowlist). Se recomienda revisión periódica de sus alcances (scopes).`;
      }
    }

    return {
      name: this.name,
      valorPrincipal: rawOutput,
      comentario055: comentario055,
      riesgo055: riesgo055,
      score055: this.calcularScoreDeRiesgo(riesgo055)
    };
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo055: "Medio", score055: 2, comentario055: msg };
  }
}