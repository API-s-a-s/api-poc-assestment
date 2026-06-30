/**
 * Estrategia para auditar el Análisis mejorado de mensajes previos a la entrega en Gmail.
 * Evalúa si el sistema retiene correos sospechosos para un escaneo profundo antes de entregarlos.
 */
class GmailEnhancedPreDeliveryScanningStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-075
    const configIDs = [
      { 
        id: "ID-075", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario075",
        riskKey: "riesgo075",
        scoreKey: "score075"
      }
    ];

    super("Gmail Enhanced Pre-Delivery Scanning Audit", configIDs);
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

    const gmailPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.enhanced_pre_delivery_message_scanning"));

    let isEnhancedScanningEnabled = false;
    let rawData = null;

    if (gmailPolicies.length === 0) {
      // Por defecto, asumimos que el escaneo mejorado está deshabilitado
      isEnhancedScanningEnabled = false;
    } else {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(gmailPolicies, "gmail.enhanced_pre_delivery_message_scanning");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-075] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-075] valueNode: ${JSON.stringify(valueNode)}`);
        
        // Verificamos el booleano específico de detección mejorada
        if (valueNode.enableImprovedSuspiciousContentDetection === true || 
            (valueNode.state && valueNode.state.toUpperCase() === 'ENABLED')) {
          isEnhancedScanningEnabled = true;
        }
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo075, comentario075;

    if (isEnhancedScanningEnabled) {
      // Caso 1: Escaneo mejorado habilitado (Seguro)
      respuestaConcreta = "Habilitado";
      riesgo075 = "Bajo";
      comentario075 = "El análisis mejorado de mensajes previos a la entrega se encuentra habilitado. Esta configuración permite a Google retener temporalmente los correos sospechosos para someterlos a un escaneo heurístico profundo, bloqueando de manera efectiva amenazas de día cero y campañas de phishing avanzadas antes de que lleguen a la bandeja de entrada.";
    } else {
      // Caso 2: Escaneo mejorado deshabilitado (Riesgo Alto por phishing de día cero)
      respuestaConcreta = "Deshabilitado";
      riesgo075 = "Alto";
      comentario075 = "El análisis profundo previo a la entrega está deshabilitado. Los correos electrónicos sospechosos se entregan de inmediato a los usuarios sin pasar por el escaneo de seguridad adicional de Google, lo que incrementa significativamente el riesgo de que los empleados interactúen con ataques de phishing, enlaces maliciosos o malware de día cero.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Enhanced Pre-Delivery Scanning Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo075}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario075: comentario075,
      riesgo075: riesgo075,
      score075: this.calcularScoreDeRiesgo(riesgo075)
    };
    }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo075: "Medio", score075: 2, comentario075: msg };
  }
}