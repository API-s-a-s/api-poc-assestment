/**
 * Estrategia para auditar a quién se le permite distribuir contenido de unidades compartidas.
 * Evalúa allowed_parties_for_distributing_content.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/drive_and_docs.external_sharing
 */
class DriveSharedDriveDistributingContentStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-101", 
        valueKey: "valorPrincipal",
        noteKey: "comentario101",
        riskKey: "riesgo101",
        scoreKey: "score101"
      }
    ];

    super("Drive Distributing Content Audit", configIDs);
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

    const targetPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("drive_and_docs.external_sharing"));
    
    let extractedValue = "NONE";
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "drive_and_docs.external_sharing");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // El usuario solicitó explícitamente usar la clave del JSON (allowed_parties_for_distributing_content)
        // Añadimos el fallback (camelCase) por si la API lo envía con ese formato.
        if (valueNode.allowed_parties_for_distributing_content !== undefined) {
            extractedValue = valueNode.allowed_parties_for_distributing_content;
        } else if (valueNode.allowedPartiesForDistributingContent !== undefined) {
            extractedValue = valueNode.allowedPartiesForDistributingContent;
        }
      }
    }

    let respuestaConcreta;
    let riesgo, comentario;

    if (extractedValue === "ALL_ELIGIBLE_USERS") {
      respuestaConcreta = "Todos los usuarios";
      riesgo = "Alto";
      comentario = "Se permite a cualquier usuario elegible distribuir contenido fuera del dominio. Esto incrementa significativamente el riesgo de fuga de datos.";
    } else if (extractedValue === "ELIGIBLE_INTERNAL_USERS") {
      respuestaConcreta = "Solo usuarios internos";
      riesgo = "Medio";
      comentario = "La distribución de contenido se restringe a usuarios internos. Disminuye la exposición pública, pero persiste el riesgo de propagación interna no autorizada.";
    } else { // NONE
      respuestaConcreta = "Nadie";
      riesgo = "Bajo";
      comentario = "La distribución de contenido está deshabilitada. Esta es la configuración más segura para evitar exfiltración desde unidades compartidas.";
    }

    Logger.log(`[LOG] Drive Distributing Content Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario101: comentario,
      riesgo101: riesgo,
      score101: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo101: "Medio", score101: 2, comentario101: msg };
  }
}
