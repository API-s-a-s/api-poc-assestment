/**
 * Estrategia para auditar la configuración predeterminada para nuevos archivos.
 * Evalúa default_file_access.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/drive_and_docs.general_access_default
 */
class DriveDefaultFileAccessStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-107", 
        valueKey: "valorPrincipal",
        noteKey: "comentario107",
        riskKey: "riesgo107",
        scoreKey: "score107"
      }
    ];

    super("Drive Default File Access Audit", configIDs);
    this.category = "Drive";
  }

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

    const targetPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("drive_and_docs.general_access_default"));
    
    let extractedValue = "PRIMARY_AUDIENCE_WITH_LINK";
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "drive_and_docs.general_access_default");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // El usuario solicitó explícitamente usar la clave del JSON (default_file_access)
        // Añadimos el fallback (camelCase) por si la API lo envía con ese formato.
        if (valueNode.default_file_access !== undefined) {
            extractedValue = valueNode.default_file_access;
        } else if (valueNode.defaultFileAccess !== undefined) {
            extractedValue = valueNode.defaultFileAccess;
        }
      }
    }

    let respuestaConcreta;
    let riesgo, comentario;

    if (extractedValue === "PRIMARY_AUDIENCE_WITH_LINK_OR_SEARCH") {
      respuestaConcreta = "Público objetivo con enlace o búsqueda";
      riesgo = "Alto";
      comentario = "La configuración predeterminada para nuevos archivos hace que sean accesibles y buscables por todo el público objetivo interno. Facilita la colaboración pero incrementa la sobreexposición interna de información por defecto.";
    } else if (extractedValue === "PRIMARY_AUDIENCE_WITH_LINK") {
      respuestaConcreta = "Público objetivo con enlace";
      riesgo = "Medio";
      comentario = "Los archivos nuevos requieren conocer el enlace para acceder, incluso dentro del público objetivo. Esto añade una ligera barrera contra el acceso inadvertido interno.";
    } else { // PRIVATE_TO_OWNER
      respuestaConcreta = "Privado (Solo el propietario)";
      riesgo = "Bajo";
      comentario = "Los nuevos archivos son completamente privados por defecto. Los usuarios deben otorgar permisos explícitamente, lo que cumple el principio de Zero Trust.";
    }

    Logger.log(`[LOG] Drive Default File Access Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario107: comentario,
      riesgo107: riesgo,
      score107: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo107: "Medio", score107: 2, comentario107: msg };
  }
}
