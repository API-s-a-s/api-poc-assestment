/**
 * Estrategia para auditar la configuración de Seguridad de Archivos Adjuntos en Gmail (Control Duplicado/Alterno).
 * Evalúa si las protecciones avanzadas contra malware y ransomware en adjuntos están activas.
 */
class GmailAttachmentSafetyId073Strategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-073
    const configIDs = [
      { 
        id: "ID-073", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario073",
        riskKey: "riesgo073",
        scoreKey: "score073"
      }
    ];

    super("Gmail Attachment Safety Audit (ID-073)", configIDs);
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
      // Por defecto, asumimos que no está habilitado
      isAttachmentSafetyEnabled = false;
    } else {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(gmailPolicies, "gmail.email_attachment_safety");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-073] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-073] valueNode: ${JSON.stringify(valueNode)}`);
        
        if (valueNode.enableEmailAttachmentSafety === true || 
            (valueNode.state && valueNode.state.toUpperCase() === 'ENABLED')) {
          isAttachmentSafetyEnabled = true;
        }
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo073, comentario073;

    if (isAttachmentSafetyEnabled) {
      // Caso 1: Protección de adjuntos habilitada (Seguro)
      respuestaConcreta = "Habilitado";
      riesgo073 = "Bajo";
      comentario073 = "La protección avanzada de archivos adjuntos (Email Attachment Safety) se encuentra habilitada. El entorno aplica barreras heurísticas y entornos aislados (sandboxing) para detectar y bloquear proactivamente la entrega de correos con malware, ransomware o scripts ejecutables no confiables.";
    } else {
      // Caso 2: Protección de adjuntos deshabilitada (Riesgo Alto)
      respuestaConcreta = "Deshabilitado";
      riesgo073 = "Alto";
      comentario073 = "La protección avanzada contra archivos adjuntos maliciosos se encuentra deshabilitada o degradada. Esta configuración expone severamente a los usuarios frente a ataques de ingeniería social y distribución de malware (como ransomware o troyanos) camuflados en documentos de uso cotidiano.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Attachment Safety Audit (ID-073): Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo073}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario073: comentario073,
      riesgo073: riesgo073,
      score073: this.calcularScoreDeRiesgo(riesgo073)
    };
    }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo073: "Medio", score073: 2, comentario073: msg };
  }
}