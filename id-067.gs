/**
 * Estrategia para auditar el uso de pasarelas de salida SMTP externas por usuario.
 * Evalúa si los usuarios pueden enviar correos a través de servidores SMTP de terceros.
 */
class GmailPerUserOutboundGatewayStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-067
    const configIDs = [
      { 
        id: "ID-067", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario067",
        riskKey: "riesgo067",
        scoreKey: "score067"
      }
    ];

    super("Gmail Per-User Outbound Gateway Audit", configIDs);
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

    const gmailPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.per_user_outbound_gateway"));

    let isOutboundGatewayEnabled = false;
    let rawData = null;

    if (gmailPolicies.length === 0) {
      // Por defecto, asumimos que no está habilitado explícitamente
      isOutboundGatewayEnabled = false;
    } else {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(gmailPolicies, "gmail.per_user_outbound_gateway");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-067] Política raíz efectiva encontrada: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-067] valueNode extraído: ${JSON.stringify(valueNode)}`);
        
        if (valueNode.enablePerUserOutboundGateway === true || 
            (valueNode.state && valueNode.state.toUpperCase() === 'ENABLED')) {
          isOutboundGatewayEnabled = true;
        }
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo067, comentario067;

    if (isOutboundGatewayEnabled) {
      // Caso 1: Pasarela SMTP externa habilitada (Riesgo Alto por evasión de DLP/Vault)
      respuestaConcreta = "Habilitado";
      riesgo067 = "Alto";
      comentario067 = "La configuración permite a los usuarios utilizar pasarelas de salida (SMTP) externas. Esto representa un alto riesgo de cumplimiento y seguridad, ya que los correos enviados a través de servidores de terceros evaden los controles de Prevención de Pérdida de Datos (DLP) del dominio, escapan de las políticas de enrutamiento y no quedan registrados en el archivo legal de Google Vault.";
    } else {
      // Caso 2: Pasarela SMTP externa deshabilitada (Seguro)
      respuestaConcreta = "Deshabilitado";
      riesgo067 = "Bajo";
      comentario067 = "El uso de pasarelas de salida (SMTP) externas por usuario se encuentra restringido de manera estricta. Todo el tráfico de correo saliente está obligado a transitar a través de la infraestructura autorizada de Google Workspace, garantizando la retención en Vault y la aplicación de políticas DLP.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Per-User Outbound Gateway Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo067}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario067: comentario067,
      riesgo067: riesgo067,
      score067: this.calcularScoreDeRiesgo(riesgo067)
    };
    }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo067: "Medio", score067: 2, comentario067: msg };
  }
}