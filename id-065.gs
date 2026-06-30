/**
 * Estrategia para auditar la configuración de reenvío automático (Auto-Forwarding) de Gmail.
 * Evalúa si los usuarios tienen permitido configurar reglas para reenviar correos a cuentas externas.
 */
class GmailAutoForwardingStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-065
    const configIDs = [
      { 
        id: "ID-065", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario065",
        riskKey: "riesgo065",
        scoreKey: "score065"
      }
    ];

    super("Gmail Auto-Forwarding Audit", configIDs);
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

    const gmailPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.auto_forwarding"));

    let isAutoForwardingEnabled = false;
    let rawData = null;

    if (gmailPolicies.length === 0) {
      // Por defecto, asumimos que no está habilitado explícitamente
      isAutoForwardingEnabled = false;
    } else {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(gmailPolicies, "gmail.auto_forwarding");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-065] Política raíz efectiva encontrada: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-065] valueNode extraído: ${JSON.stringify(valueNode)}`);
        
        if (valueNode.enableAutoForwarding === true || 
            (valueNode.state && valueNode.state.toUpperCase() === 'ENABLED')) {
          isAutoForwardingEnabled = true;
        }
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo065, comentario065;

    if (isAutoForwardingEnabled) {
      // Caso 1: Reenvío automático habilitado (Riesgo Alto por exfiltración)
      respuestaConcreta = "Habilitado";
      riesgo065 = "Alto";
      comentario065 = "El reenvío automático de correos (Auto-Forwarding) se encuentra habilitado en el dominio. Esto representa una vulnerabilidad crítica de exfiltración de datos, ya que permite a usuarios (o atacantes en cuentas comprometidas) configurar reglas para desviar silenciosamente copias de correos corporativos hacia direcciones personales o externas.";
    } else {
      // Caso 2: Reenvío automático deshabilitado (Seguro)
      respuestaConcreta = "Deshabilitado";
      riesgo065 = "Bajo";
      comentario065 = "El reenvío automático de correos se encuentra restringido. Se impide que los usuarios configuren reglas de enrutamiento que envíen automáticamente los mensajes entrantes hacia cuentas externas, garantizando que el flujo de información permanezca dentro del perímetro seguro de la organización.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Gmail Auto-Forwarding Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo065}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario065: comentario065,
      riesgo065: riesgo065,
      score065: this.calcularScoreDeRiesgo(riesgo065)
    };
    }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo065: "Medio", score065: 2, comentario065: msg };
  }
}