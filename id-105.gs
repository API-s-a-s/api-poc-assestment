/**
 * Estrategia para auditar si se permite agregar a no miembros a archivos individuales.
 * Evalúa allow_non_member_access.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/drive_and_docs.shared_drive_creation
 */
class DriveAllowNonMemberAccessStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-105", 
        valueKey: "valorPrincipal",
        noteKey: "comentario105",
        riskKey: "riesgo105",
        scoreKey: "score105"
      }
    ];

    super("Drive Allow Non Member Access Audit", configIDs);
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
        
        // El usuario solicitó explícitamente usar la clave del JSON (allow_non_member_access)
        // Añadimos el fallback (camelCase) por si la API lo envía con ese formato.
        if (valueNode.allow_non_member_access !== undefined) {
            extractedValue = valueNode.allow_non_member_access;
        } else if (valueNode.allowNonMemberAccess !== undefined) {
            extractedValue = valueNode.allowNonMemberAccess;
        }
      }
    }

    let respuestaConcreta;
    let riesgo, comentario;

    if (extractedValue === true) {
      respuestaConcreta = "Habilitado";
      riesgo = "Medio";
      comentario = "Se permite agregar a usuarios que no son miembros de la unidad compartida a archivos individuales. Esto debilita la estructura de control de acceso basada en grupos/unidades, dificultando la auditoría de quién tiene acceso a qué.";
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo = "Bajo";
      comentario = "No se permite agregar a no miembros. El acceso a los archivos está estrictamente limitado a los miembros autorizados de la unidad compartida, fortaleciendo el principio del mínimo privilegio.";
    }

    Logger.log(`[LOG] Drive Allow Non Member Access Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario105: comentario,
      riesgo105: riesgo,
      score105: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo105: "Medio", score105: 2, comentario105: msg };
  }
}
