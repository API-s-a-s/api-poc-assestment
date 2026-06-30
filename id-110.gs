/**
 * Estrategia para auditar si se permite Google Drive para escritorio en la organización.
 * Evalúa allow_drive_for_desktop.
 * setting.type: settings/drive_and_docs.drive_for_desktop
 */
class DriveForDesktopStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-110", 
        valueKey: "valorPrincipal",
        noteKey: "comentario110",
        riskKey: "riesgo110",
        scoreKey: "score110"
      }
    ];

    super("Drive for Desktop Audit", configIDs);
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

    const targetPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("drive_and_docs.drive_for_desktop"));
    
    let extractedValue = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "drive_and_docs.drive_for_desktop");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        if (valueNode.allow_drive_for_desktop !== undefined) {
            extractedValue = valueNode.allow_drive_for_desktop;
        } else if (valueNode.allowDriveForDesktop !== undefined) {
            extractedValue = valueNode.allowDriveForDesktop;
        }
      }
    }

    let respuestaConcreta, riesgo, comentario;

    if (extractedValue === true) {
      respuestaConcreta = "Habilitado";
      riesgo = "Medio";
      comentario = "Se permite el uso de Drive para escritorio. Los usuarios pueden sincronizar archivos corporativos en sus equipos locales, lo que puede suponer un riesgo si los equipos no están bajo gestión de MDM o políticas de cumplimiento (Compliance).";
    } else if (extractedValue === false) {
      respuestaConcreta = "Deshabilitado";
      riesgo = "Bajo";
      comentario = "Drive para escritorio está inhabilitado. Los archivos no se pueden sincronizar de forma masiva a nivel local, mitigando el riesgo de extracción de datos masiva hacia dispositivos no gestionados.";
    } else {
      respuestaConcreta = "Revisión manual";
      riesgo = "Medio";
      comentario = "La configuración no está explícitamente definida por la política, por lo que hereda el comportamiento predeterminado.";
    }

    Logger.log(`[LOG] Drive for Desktop Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario110: comentario,
      riesgo110: riesgo,
      score110: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo110: "Medio", score110: 2, comentario110: msg };
  }
}
