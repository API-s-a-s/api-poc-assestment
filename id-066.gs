/**
 * Estrategia para auditar la evasión (bypass) del proxy de imágenes de Gmail.
 * Evalúa si las imágenes se descargan directamente exponiendo la IP del usuario.
 */
class GmailImageProxyBypassStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para el ID-066 (Ajustado según tu corrección)
    const configIDs = [
      { 
        id: "ID-066", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario066",
        riskKey: "riesgo066",
        scoreKey: "score066"
      }
    ];

    super("Gmail Image Proxy Bypass Audit", configIDs);
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

    const gmailPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.email_image_proxy_bypass"));

    let isBypassEnabled = false;
    let rawData = null;

    if (gmailPolicies.length === 0) {
      // Por defecto, asumimos que el bypass no está habilitado
      isBypassEnabled = false;
    } else {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(gmailPolicies, "gmail.email_image_proxy_bypass");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-066] Política raíz efectiva encontrada: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-066] valueNode extraído: ${JSON.stringify(valueNode)}`);
        
        if (valueNode.enableEmailImageProxyBypass === true || 
            (valueNode.state && valueNode.state.toUpperCase() === 'ENABLED')) {
          isBypassEnabled = true;
        }
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo066, comentario066;

    if (isBypassEnabled) {
      // Caso 1: Bypass habilitado (Riesgo Alto por exposición de IP y tracking)
      respuestaConcreta = "Habilitado";
      riesgo066 = "Alto";
      comentario066 = "La evasión (bypass) del proxy de imágenes de Gmail se encuentra habilitada en el dominio. Esto representa un alto riesgo de privacidad y seguridad, ya que permite que los correos descarguen imágenes directamente de servidores de terceros, exponiendo la dirección IP, geolocalización y confirmaciones de lectura de los usuarios ante posibles atacantes o rastreadores.";
    } else {
      // Caso 2: Bypass deshabilitado (Seguro)
      respuestaConcreta = "Deshabilitado";
      riesgo066 = "Bajo";
      comentario066 = "La evasión del proxy de imágenes se encuentra deshabilitada. Todas las imágenes contenidas en correos externos son filtradas y servidas obligatoriamente a través de los servidores proxy seguros de Google, ocultando las direcciones IP reales de los usuarios y bloqueando píxeles de rastreo maliciosos.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Image Proxy Bypass Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo066}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario066: comentario066,
      riesgo066: riesgo066,
      score066: this.calcularScoreDeRiesgo(riesgo066)
    };
    }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo066: "Medio", score066: 2, comentario066: msg };
  }
}  