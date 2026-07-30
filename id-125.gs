/**
 * Estrategia para auditar los permisos de temas de vista predeterminados en Google Groups.
 * Evalúa el parámetro viewTopicsDefaultAccessLevel.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/groups_for_business.groups_sharing
 */
class GroupsViewTopicsDefaultAccessStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-125", 
        valueKey: "valorPrincipal",
        noteKey: "comentario125",
        riskKey: "riesgo125",
        scoreKey: "score125"
      }
    ];

    super("Groups Default View Topics Access Audit", configIDs);
    this.category = "Servicios adicionales";
    this.customerId = customerId;
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
    const { policies, auth } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    Logger.log(`[DEBUG ID-125] Total de políticas en contexto global: ${policies.length}`);

    // Filtramos las políticas pertenecientes al entorno de Groups Sharing
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("groups_for_business.groups_sharing")
    );
    
    Logger.log(`[ID-125] Se encontraron ${targetPolicies.length} políticas en memoria mediante filtro .endsWith()`);
    
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[ID-125] [WARNING] La API masiva no trajo la configuración. Iniciando consulta directa a la API...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*groups_for_business.groups_sharing.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const json = JSON.parse(response.getContentText());
        targetPolicies = json.policies || [];
      } catch (e) {
        Logger.log(`[ID-125] Error crítico en transporte HTTP directo: ${e.message}`);
      }
    }

    let extractedValue = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "groups_for_business.groups_sharing");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;

        if (valueNode.viewTopicsDefaultAccessLevel !== undefined) {
          extractedValue = valueNode.viewTopicsDefaultAccessLevel;
        } else if (valueNode.view_topics_default_access_level !== undefined) {
          extractedValue = valueNode.view_topics_default_access_level;
        }
        
        Logger.log(`[DEBUG ID-125] Valor final de la variable extraído: ${extractedValue}`);
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Mapeo exhaustivo de Enums de visibilidad perimetral de Cloud Identity Policy API
    if (
      extractedValue === "ANYONE_IN_THE_WORLD" || 
      extractedValue === "ANYONE_CAN_VIEW" || 
      extractedValue === "PUBLIC"
    ) {
      respuestaConcreta = "Cualquiera en internet";
      riesgo = "Alto";
      comentario = "La configuración predeterminada permite que cualquier usuario en internet vea los temas, debates e hilos de discusión de los grupos de la organización. Esto representa una fuga crítica de información institucional y de propiedad intelectual.";
    } else if (
      extractedValue === "DOMAIN_USERS" || 
      extractedValue === "ALL_YOUR_ORGANIZATION_MEMBERS" || 
      extractedValue === "ALL_IN_DOMAIN_CAN_VIEW"
    ) {
      respuestaConcreta = "Todos los miembros de la organización";
      riesgo = "Medio";
      comentario = "Cualquier empleado o miembro del dominio puede ver por defecto los temas y discusiones de cualquier grupo creado. Aunque el perímetro es interno, incrementa el riesgo de exposición de datos sensibles entre departamentos no autorizados.";
    } else if (
      extractedValue === "ALL_GROUP_MEMBERS" || 
      extractedValue === "ALL_MEMBERS_CAN_VIEW" || 
      extractedValue === "MEMBER" || 
      extractedValue === "MEMBERS_ONLY"
    ) {
      respuestaConcreta = "Solo miembros del grupo";
      riesgo = "Bajo";
      comentario = "La visibilidad por defecto de los temas está restricted exclusivamente a los integrantes aprobados de cada grupo, garantizando el aislamiento de la información y el principio de menor privilegio.";
    } else if (
      extractedValue === "ALL_MANAGERS_CAN_VIEW" || 
      extractedValue === "MANAGERS_ONLY" || 
      extractedValue === "OWNERS_AND_MANAGERS"
    ) {
      respuestaConcreta = "Solo administradores del grupo";
      riesgo = "Bajo";
      comentario = "Acceso altamente restringido. Por defecto, solo los gerentes o administradores del grupo pueden ver el contenido de los temas y discusiones.";
    } else {
      // Si viniera vacío o nulo de fábrica
      respuestaConcreta = "Solo miembros del grupo";
      riesgo = "Bajo";
      comentario = "Google Workspace aplica el comportamiento predeterminado seguro del sistema, aislando las discusiones de los grupos únicamente a sus miembros.";
    }

    Logger.log(`[LOG] Groups Default View Topics Access Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Extracted: ${extractedValue}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario125: comentario,
      riesgo125: riesgo,
      score125: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-125] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo125: "Medio", score125: 2, comentario125: msg };
  }
}