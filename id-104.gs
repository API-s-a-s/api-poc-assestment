/**
 * Estrategia para auditar si se permite acceso externo a archivos en unidades compartidas.
 * Evalúa allow_external_user_access.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/drive_and_docs.shared_drive_creation
 */
class DriveAllowExternalUserAccessStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-104", 
        valueKey: "valorPrincipal",
        noteKey: "comentario104",
        riskKey: "riesgo104",
        scoreKey: "score104"
      }
    ];

    super("Drive Allow External User Access Audit", configIDs);
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

    const targetPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("drive_and_docs.shared_drive_creation"));
    
    let extractedValue = true;
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "drive_and_docs.shared_drive_creation");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // El usuario solicitó explícitamente usar la clave del JSON (allow_external_user_access)
        // Añadimos el fallback (camelCase) por si la API lo envía con ese formato.
        if (valueNode.allow_external_user_access !== undefined) {
            extractedValue = valueNode.allow_external_user_access;
        } else if (valueNode.allowExternalUserAccess !== undefined) {
            extractedValue = valueNode.allowExternalUserAccess;
        }
      }
    }

    let respuestaConcreta;
    let riesgo, comentario;

    if (extractedValue === true) {
      respuestaConcreta = "Habilitado";
      riesgo = "Alto";
      comentario = "Se permite el acceso de usuarios externos a archivos dentro de las unidades compartidas. Esto representa un riesgo directo de exposición de información confidencial hacia entidades ajenas a la organización.";
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo = "Bajo";
      comentario = "El acceso a usuarios externos está bloqueado para las unidades compartidas. La información permanece contenida dentro del perímetro de la organización.";
    }

    Logger.log(`[LOG] Drive Allow External User Access Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario104: comentario,
      riesgo104: riesgo,
      score104: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo104: "Medio", score104: 2, comentario104: msg };
  }
}
