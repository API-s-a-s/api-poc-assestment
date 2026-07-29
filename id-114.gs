/**
 * Estrategia para auditar los complementos permitidos desde la tienda (Marketplace Allowlist).
 * Evalúa el número de aplicaciones permitidas en workspace_marketplace.apps_allowlist.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/workspace_marketplace.apps_allowlist
 */
class WorkspaceMarketplaceAppsAllowlistStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-114", 
        valueKey: "valorPrincipal",
        noteKey: "comentario114",
        riskKey: "riesgo114",
        scoreKey: "score114"
      }
    ];

    super("Workspace Marketplace Apps Allowlist Audit", configIDs);
    this.category = "Drive";
  }

  // Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    // Filtramos las políticas pertenecientes al Marketplace de la organización
    const targetPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("workspace_marketplace.apps_allowlist"));
    
    let allowedAppsCount = 0;
    let rawData = null;
    let hasPolicy = false;

    if (targetPolicies.length > 0) {
      // Resolvemos los conflictos utilizando el reductor por defecto (Max) para directivas SYSTEM
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "workspace_marketplace.apps_allowlist");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        hasPolicy = true;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // Extraemos la lista o matriz de aplicaciones autorizadas
        const appsList = valueNode.apps || valueNode.appsList || [];
        allowedAppsCount = Array.isArray(appsList) ? appsList.length : 0;
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // =======================================================================
    // LÓGICA DE NEGOCIO Y DICTAMEN DE AUDITORÍA (ID-114)
    // =======================================================================
    if (hasPolicy) {
      respuestaConcreta = `${allowedAppsCount} app(s)`;
      
      if (allowedAppsCount > 0) {
        riesgo = "Medio";
        comentario = `${allowedAppsCount} aplicaciones están permitidas en la lista blanca del Marketplace.`;
      } else {
        riesgo = "Bajo";
        comentario = `${allowedAppsCount} aplicaciones están permitidas en la lista blanca del Marketplace.`;
      }
    } else {
      respuestaConcreta = "Revisión manual";
      riesgo = "Medio";
      comentario = "La configuración no está explícitamente definida por la política, por lo que hereda el comportamiento predeterminado.";
    }

    Logger.log(`[LOG] Workspace Marketplace Apps Allowlist Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo}`);

    // Retorno consolidado mapeado con la matriz del Sheets
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario114: comentario,
      riesgo114: riesgo,
      score114: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-114] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo114: "Medio", score114: 2, comentario114: msg };
  }
}