/**
 * Estrategia para auditar si se permite que aplicaciones de terceros accedan a los datos del directorio interno.
 * Evalúa el parámetro sharing_option / sharingOption.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/directory.external_directory_sharing
 */
class ContactsExternalDirectorySharingStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-123", 
        valueKey: "valorPrincipal",
        noteKey: "comentario123",
        riskKey: "riesgo123",
        scoreKey: "score123"
      }
    ];

    super("Contacts External Directory Sharing Audit", configIDs);
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

    Logger.log(`[DEBUG ID-123] Total de políticas recibidas en memoria global: ${policies.length}`);

    // Filtramos las políticas pertenecientes al sub-entorno de Directory (external sharing)
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("directory.external_directory_sharing")
    );
    
    Logger.log(`[ID-123] Se encontraron ${targetPolicies.length} políticas en memoria mediante filtro .endsWith()`);
    
    // Fallback directo a la API si no vino en memoria
    if (targetPolicies.length === 0 && auth) {
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*directory.external_directory_sharing.*")`;
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
        Logger.log(`[ID-123] Error en consulta directa a API: ${e.message}`);
      }
    }

    let extractedValue = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "directory.external_directory_sharing");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        extractedValue = valueNode.sharing_option || valueNode.sharingOption || null;
        Logger.log(`[DEBUG ID-123] Valor extraído final: ${extractedValue}`);
      }
    }

    let respuestaConcreta, riesgo, comentario;

    if (extractedValue === "REQUESTER_BASIC_PROFILE_ONLY") {
      respuestaConcreta = "Campos básicos de usuario autenticado";
      riesgo = "Bajo";
      comentario = "Solo se comparte el nombre, foto y correo del usuario autenticado con aplicaciones externas.";
    } else if (extractedValue === "ORGANIZATION_DIRECTORY_DATA") {
      respuestaConcreta = "Campos básicos de usuarios autenticados y organización";
      riesgo = "Alto";
      comentario = "Se comparte toda la información del directorio de la organización (contactos y perfiles) con aplicaciones externas.";
    } else if (extractedValue === "SHARING_OPTION_UNSPECIFIED") {
      respuestaConcreta = "No especificado";
      riesgo = "";
      comentario = "Configuración no especificada de forma explícita en las políticas del dominio.";
    } else {
      // Valor predeterminado de fábrica si no hay política explícita
      respuestaConcreta = "Campos básicos de perfiles y la organización (Predeterminado)";
      riesgo = "Alto";
      comentario = "Google Workspace permite por defecto que aplicaciones externas accedan a toda la información del directorio corporativo.";
    }

    Logger.log(`[LOG] Contacts External Directory Sharing Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Extracted: ${extractedValue}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario123: comentario,
      riesgo123: riesgo,
      score123: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-123] ERROR: ${msg}`);
    return { name: this.name, valorPrincipal: "ERROR", riesgo123: "Medio", score123: 2, comentario123: msg };
  }
}