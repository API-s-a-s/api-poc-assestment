/**
 * Estrategia para auditar los permisos de acceso a las APIs de Google Services.
 * Verifica qué servicios están restringidos para aplicaciones de terceros.
 * Utiliza Cloud Identity API (consulta directa).
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
    
    // Diccionario de enums de servicios de Google Workspace (según respuesta real de la API)
    // La API devuelve scopesGroup como "CLASSROOM_ALL", "DRIVE_ALL", "GMAIL_ALL", etc.
    this.GOOGLE_WORKSPACE_SERVICES = [
      "DRIVE", "GMAIL", "CALENDAR", "CLASSROOM", "CONTACTS", "CHAT", "MEET", "VAULT", "GROUPS"
    ];
  }

  evaluateInMemory(globalContext) {
    const { auth, policies } = globalContext;
    if (!auth) return this._buildErrorResponse("Falta el contexto de autenticación (auth) en globalContext.");

    Logger.log(`[ID-044] Iniciando evaluación para api_controls.google_services...`);

    let restrictedCount = 0;
    let totalServices = 0;
    let isDriveRestricted = false;
    let isGmailRestricted = false;
    let restrictedServicesList = [];

    // Buscamos la política en la carga masiva (bulk)
    let servicePolicies = [];
    if (policies) {
      servicePolicies = policies.filter(p => {
        const st = (p.setting && p.setting.type) || "";
        return st === "settings/api_controls.google_services" || st.includes("api_controls.google_services");
      });
    }

    // Fallback: si no está en bulk, consultar directamente a la API
    if (servicePolicies.length === 0) {
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*api_controls.google_services.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" }
        };

        const response = this.fetchWithBackoff(url, options);
        const json = JSON.parse(response.getContentText());
        servicePolicies = json.policies || [];
      } catch (e) {
        Logger.log(`[ID-044] Error al consultar la API directamente: ${e.message}`);
        return this._buildErrorResponse(`Error al consultar la API: ${e.message}`);
      }
    }

    if (servicePolicies.length > 0) {
      // Obtenemos la política efectiva
      let rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(servicePolicies, "api_controls.google_services");
      if (!rootPolicy) {
        rootPolicy = PolicyReducerFactory.reduce(servicePolicies, "api_controls.google_services");
      }
      if (!rootPolicy && servicePolicies.length > 0) {
        rootPolicy = servicePolicies[0];
      }

      if (rootPolicy && rootPolicy.setting) {
        const configNode = rootPolicy.setting.value || rootPolicy.setting;
        const services = configNode.services || [];
        
        services.forEach(s => {
          const scopeGroup = (s.scopesGroup || s.scopes_group || s.service_name || s.name || "").toUpperCase();
          
          let isWorkspaceService = false;
          for (const key of this.GOOGLE_WORKSPACE_SERVICES) {
            if (scopeGroup.includes(key)) {
              isWorkspaceService = true;
              break;
            }
          }

          if (isWorkspaceService) {
            totalServices++;
            // isEnabled === false significa que está restringido
            const isRestricted = s.isEnabled === false || s.is_enabled === false;
            
            if (isRestricted) {
              restrictedCount++;
              restrictedServicesList.push(scopeGroup);
              Logger.log(`[ID-044] Servicio restringido detectado: ${scopeGroup}`);
              if (scopeGroup.includes("DRIVE")) isDriveRestricted = true;
              if (scopeGroup.includes("GMAIL")) isGmailRestricted = true;
            }
          }
        });
      }
    } else {
       Logger.log(`[ID-044] No se encontraron políticas de api_controls.google_services para este customer.`);
    }

    Logger.log(`[ID-044] Total: ${restrictedCount} servicios restringidos de ${totalServices} evaluados`);

    let riesgo044, comentario044, valorPrincipalFormateado;
    if (restrictedCount === 0) {
      riesgo044 = "Alto";
      valorPrincipalFormateado = "0 restringidos";
      comentario044 = "Vulnerabilidad de Exposición (Shadow IT): Ningún servicio base de Google Workspace se encuentra restringido. Aplicaciones de terceros pueden solicitar acceso libre a la información corporativa.";
    } else {
      valorPrincipalFormateado = `${restrictedCount} restringidos`;
      const appsBloqueadas = restrictedServicesList.length > 0 ? ` (Apps bloqueadas: ${restrictedServicesList.join(", ")})` : "";
      if (isDriveRestricted && isGmailRestricted) {
        riesgo044 = "Bajo";
        comentario044 = `Cumplimiento Zero Trust: ${restrictedCount} de ${totalServices > 0 ? totalServices : 'varios'} servicios de Workspace están restringidos frente a terceros, blindando los vectores críticos de la compañía (Drive y Gmail).${appsBloqueadas}`;
      } else {
        riesgo044 = "Medio";
        comentario044 = `Restricción Incompleta: Existen ${restrictedCount} servicio(s) restringido(s)${appsBloqueadas}, pero los aplicativos de mayor riesgo (Google Drive y/o Gmail) NO se encuentran explícitamente restringidos contra terceros.`;
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