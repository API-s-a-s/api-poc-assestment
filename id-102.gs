/**
 * Estrategia para auditar si se evita que los usuarios creen nuevas unidades compartidas.
 * Evalúa allow_shared_drive_creation.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/drive_and_docs.shared_drive_creation
 */
class DrivePreventSharedDriveCreationStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-102", 
        valueKey: "valorPrincipal",
        noteKey: "comentario102",
        riskKey: "riesgo102",
        scoreKey: "score102"
      }
    ];

    super("Drive Prevent Shared Drive Creation Audit", configIDs);
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
    
    let extractedValue = null; // No asumimos true si viene vacío
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "drive_and_docs.shared_drive_creation");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // El usuario solicitó explícitamente usar la clave del JSON (allow_shared_drive_creation)
        // Añadimos el fallback (camelCase) por si la API lo envía con ese formato.
        if (valueNode.allow_shared_drive_creation !== undefined) {
            extractedValue = valueNode.allow_shared_drive_creation;
        } else if (valueNode.allowSharedDriveCreation !== undefined) {
            extractedValue = valueNode.allowSharedDriveCreation;
        }
      }
    }

    let respuestaConcreta;
    let riesgo, comentario;

    // Inversión Lógica
    if (extractedValue === true) {
      respuestaConcreta = "No evita creación (Habilitado)";
      riesgo = "Medio";
      comentario = "La restricción está inactiva (valor true). Los usuarios pueden crear nuevas unidades compartidas, lo que puede resultar en proliferación descontrolada y pérdida de visibilidad administrativa.";
    } else if (extractedValue === false) {
      respuestaConcreta = "Evita creación (Deshabilitado)";
      riesgo = "Bajo";
      comentario = "La restricción está activa (valor false). Se evita que los usuarios comunes creen nuevas unidades compartidas, manteniendo el control centralizado por parte de los administradores.";
    } else {
      respuestaConcreta = "No definido (Asume inactivo)";
      riesgo = "Medio";
      comentario = "La configuración no está explícitamente definida por la política, por lo que hereda el comportamiento predeterminado que no evita activamente la creación de unidades.";
    }

    Logger.log(`[LOG] Drive Prevent Shared Drive Creation Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario102: comentario,
      riesgo102: riesgo,
      score102: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo102: "Medio", score102: 2, comentario102: msg };
  }
}
