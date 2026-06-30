/**
 * Estrategia para auditar si se permite a lectores descargar, imprimir y copiar archivos.
 * Evalúa allowed_parties_for_download_print_copy.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/drive_and_docs.shared_drive_creation
 */
class DriveAllowedPartiesDownloadPrintCopyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-106", 
        valueKey: "valorPrincipal",
        noteKey: "comentario106",
        riskKey: "riesgo106",
        scoreKey: "score106"
      }
    ];

    super("Drive Parties Download Print Copy Audit", configIDs);
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
    
    let extractedValue = "ALL";
    let rawData = null;

    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "drive_and_docs.shared_drive_creation");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // El usuario solicitó explícitamente usar la clave del JSON (allowed_parties_for_download_print_copy)
        // Añadimos el fallback (camelCase) por si la API lo envía con ese formato.
        if (valueNode.allowed_parties_for_download_print_copy !== undefined) {
            extractedValue = valueNode.allowed_parties_for_download_print_copy;
        } else if (valueNode.allowedPartiesForDownloadPrintCopy !== undefined) {
            extractedValue = valueNode.allowedPartiesForDownloadPrintCopy;
        }
      }
    }

    let respuestaConcreta;
    let riesgo, comentario;

    if (extractedValue === "ALL") {
      respuestaConcreta = "Todos (Lectores pueden)";
      riesgo = "Alto";
      comentario = "Todos los usuarios (incluyendo lectores) pueden descargar, imprimir y copiar los archivos. Supone un riesgo alto de DLP ya que los usuarios sin privilegios de edición pueden extraer copias de la información.";
    } else if (extractedValue === "EDITORS_ONLY") {
      respuestaConcreta = "Solo Editores";
      riesgo = "Medio";
      comentario = "Solo los editores pueden descargar, imprimir y copiar. Es más seguro, aunque los editores siguen teniendo la capacidad de extraer los datos fuera del entorno controlado.";
    } else { // MANAGERS_ONLY
      respuestaConcreta = "Solo Administradores (Managers)";
      riesgo = "Bajo";
      comentario = "Únicamente los administradores de la unidad pueden extraer copias del contenido. Excelente control contra la fuga de datos.";
    }

    Logger.log(`[LOG] Drive Parties Download Print Copy Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario106: comentario,
      riesgo106: riesgo,
      score106: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo106: "Medio", score106: 2, comentario106: msg };
  }
}
