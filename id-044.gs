/**
 * Estrategia para auditar los permisos de acceso a las APIs de Google Services.
 * Verifica qué servicios están restringidos para aplicaciones de terceros.
 * Utiliza Cloud Identity API en memoria
 */
class GoogleServicesApiControlStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-044", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario044",
        riskKey: "riesgo044",
        scoreKey: "score044"
      }
    ];

    super("Google Services API Controls Audit", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Integración de aplicaciones";
  }

  evaluateInMemory(globalContext) {
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    const targetPolicies = policies.filter(p => p.setting && (p.setting.type || "").includes("api_controls.google_services"));

    let restrictedCount = 0;
    let totalServices = 0;
    let isDriveRestricted = false;
    let isGmailRestricted = false;
    const workspaceEnums = ["DRIVE_ALL", "DRIVE_HIGH_RISK", "GMAIL_ALL", "GMAIL_HIGH_RISK", "CALENDAR_ALL", "CONTACTS_ALL", "VAULT_ALL", "GROUPS", "CHAT", "MEET"];

    if (targetPolicies.length > 0) {
      let rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "api_controls.google_services");
      
      // Fallback si la API de controles no devuelve la firma de rootPolicy clásica:
      if (!rootPolicy) {
        rootPolicy = PolicyReducerFactory.reduce(targetPolicies, "api_controls.google_services");
      }
      
      if (rootPolicy && rootPolicy.setting) {
        const configNode = rootPolicy.setting.value || rootPolicy.setting;
        const services = configNode.services || [];
        
        services.forEach(s => {
          const scopeGroup = (s.scopes_group || s.scopesGroup || "").toUpperCase();
          if (workspaceEnums.includes(scopeGroup)) {
            totalServices++;
            const isRestricted = s.is_enabled === true || s.isEnabled === true;
            if (isRestricted) {
              restrictedCount++;
              if (scopeGroup.includes("DRIVE")) isDriveRestricted = true;
              if (scopeGroup.includes("GMAIL")) isGmailRestricted = true;
            }
          }
        });
      }
    }

    let riesgo044, comentario044, valorPrincipalFormateado;
    if (restrictedCount === 0) {
      riesgo044 = "Alto";
      valorPrincipalFormateado = "0 restringidos";
      comentario044 = "Vulnerabilidad de Exposición (Shadow IT): Ningún servicio base de Google Workspace se encuentra restringido. Aplicaciones de terceros pueden solicitar acceso libre a la información corporativa.";
    } else {
      valorPrincipalFormateado = `${restrictedCount} restringidos`;
      if (isDriveRestricted && isGmailRestricted) {
        riesgo044 = "Bajo";
        comentario044 = `Cumplimiento Zero Trust: ${restrictedCount} de ${totalServices} servicios de Workspace están restringidos frente a terceros, blindando los vectores críticos de la compañía (Drive y Gmail).`;
      } else {
        riesgo044 = "Medio";
        comentario044 = `Restricción Incompleta: Existen ${restrictedCount} servicio(s) restringido(s), pero los aplicativos de mayor riesgo (Google Drive y/o Gmail) NO se encuentran explícitamente restringidos contra terceros.`;
      }
    }

    return { name: this.name, valorPrincipal: valorPrincipalFormateado, comentario044: comentario044, riesgo044: riesgo044, score044: this.calcularScoreDeRiesgo(riesgo044) };
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
    return { name: this.name, valorPrincipal: "ERROR", riesgo044: "Medio", score044: 2, comentario044: msg };
  }
}