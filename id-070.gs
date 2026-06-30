/**
 * Estrategia para auditar la configuración de Seguridad de Archivos Adjuntos en Gmail.
 * Evalúa si las protecciones avanzadas contra malware y ransomware en adjuntos están activas.
 */
class GmailAttachmentSafetyStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-070
    const configIDs = [
      { 
        id: "ID-070", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario070",
        riskKey: "riesgo070",
        scoreKey: "score070"
      }
    ];

    super("Gmail Attachment Safety Audit", configIDs);
    this.category = "Email y DNS";
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
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    const gmailPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.email_attachment_safety"));

    let isAttachmentSafetyEnabled = false;
    let rawData = null;

    if (gmailPolicies.length === 0) {
      // Por defecto, asumimos que no está habilitado explícitamente
      isAttachmentSafetyEnabled = false;
    } else {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(gmailPolicies, "gmail.email_attachment_safety");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-070] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-070] valueNode: ${JSON.stringify(valueNode)}`);
        
        if (valueNode.enableEmailAttachmentSafety === true || 
            (valueNode.state && valueNode.state.toUpperCase() === 'ENABLED')) {
          isAttachmentSafetyEnabled = true;
        }
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo070, comentario070;

    if (isAttachmentSafetyEnabled) {
      // Caso 1: Protección de adjuntos habilitada (Seguro)
      respuestaConcreta = "Habilitado";
      riesgo070 = "Bajo";
      comentario070 = "La protección avanzada de archivos adjuntos (Email Attachment Safety) se encuentra habilitada. El entorno aplica barreras heurísticas y entornos aislados (sandboxing) para detectar y bloquear proactivamente la entrega de correos con malware, ransomware o scripts ejecutables no confiables.";
    } else {
      // Caso 2: Protección de adjuntos deshabilitada (Riesgo Alto por malware/ransomware)
      respuestaConcreta = "Deshabilitado";
      riesgo070 = "Alto";
      comentario070 = "La protección avanzada contra archivos adjuntos maliciosos se encuentra deshabilitada o degradada. Esta configuración expone severamente a los usuarios frente a ataques de ingeniería social y distribución de malware (como ransomware o troyanos) camuflados en documentos de uso cotidiano.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Attachment Safety Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo070}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario070: comentario070,
      riesgo070: riesgo070,
      score070: this.calcularScoreDeRiesgo(riesgo070)
    };
    }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo070: "Medio", score070: 2, comentario070: msg };
  }
}