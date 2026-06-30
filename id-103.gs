/**
 * Estrategia para auditar si se permite a miembros Administradores anular configuración.
 * Evalúa allow_managers_to_override_settings.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/drive_and_docs.shared_drive_creation
 */
class DriveAllowManagersToOverrideStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-103", 
        valueKey: "valorPrincipal",
        noteKey: "comentario103",
        riskKey: "riesgo103",
        scoreKey: "score103"
      }
    ];

    super("Drive Allow Managers to Override Audit", configIDs);
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
        
        // El usuario solicitó explícitamente usar la clave del JSON (allow_managers_to_override_settings)
        // Añadimos el fallback (camelCase) por si la API lo envía con ese formato.
        if (valueNode.allow_managers_to_override_settings !== undefined) {
            extractedValue = valueNode.allow_managers_to_override_settings;
        } else if (valueNode.allowManagersToOverrideSettings !== undefined) {
            extractedValue = valueNode.allowManagersToOverrideSettings;
        }
      }
    }

    let respuestaConcreta;
    let riesgo, comentario;

    if (extractedValue === true) {
      respuestaConcreta = "Habilitado";
      riesgo = "Medio";
      comentario = "Los administradores (managers) de las unidades compartidas pueden anular las configuraciones predeterminadas. Esto delega el control, pero puede generar configuraciones inconsistentes o inseguras si no están capacitados.";
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo = "Bajo";
      comentario = "La anulación de configuraciones por parte de managers está deshabilitada. Las políticas centralizadas se aplican obligatoriamente, garantizando coherencia en la seguridad.";
    }

    Logger.log(`[LOG] Drive Allow Managers to Override Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario103: comentario,
      riesgo103: riesgo,
      score103: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo103: "Medio", score103: 2, comentario103: msg };
  }
}
