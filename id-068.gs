/**
 * Estrategia para auditar la configuración de Enlaces e Imágenes Externas en Gmail.
 * Evalúa si las imágenes y los enlaces se muestran automáticamente o requieren confirmación.
 */
class GmailLinksAndExternalImagesStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-068
    const configIDs = [
      { 
        id: "ID-068", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario068",
        riskKey: "riesgo068",
        scoreKey: "score068"
      }
    ];

    super("Gmail Links and External Images Audit", configIDs);
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

    const gmailPolicies = policies.filter(p => p.setting && (p.setting.type || "").endsWith("gmail.links_and_external_images"));

    let isAutoDisplayEnabled = false;
    let rawData = null;

    if (gmailPolicies.length === 0) {
      // Por defecto, asumimos que no está habilitado explícitamente
      isAutoDisplayEnabled = false;
    } else {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(gmailPolicies, "gmail.links_and_external_images");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-068] Política raíz efectiva encontrada: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-068] valueNode extraído: ${JSON.stringify(valueNode)}`);
        
        // La API v1 devuelve campos como enableExternalImageScanning
        // Si el escaneo está deshabilitado, asumimos que se muestran automáticamente (riesgo)
        if (valueNode.enableExternalImageScanning === false || 
            (valueNode.state && valueNode.state.toUpperCase() === 'ENABLED')) {
          isAutoDisplayEnabled = true;
        }
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo068, comentario068;

    if (isAutoDisplayEnabled) {
      // Caso 1: Se muestran automáticamente (Riesgo Medio)
      respuestaConcreta = "Habilitado";
      riesgo068 = "Medio";
      comentario068 = "La configuración permite cargar y mostrar automáticamente imágenes externas y enlaces en los correos electrónicos. Esto representa un riesgo moderado, ya que facilita el rastreo de lectura por parte de terceros (mediante píxeles invisibles) y aumenta la probabilidad de que los usuarios interactúen con contenido malicioso o campañas de phishing.";
    } else {
      // Caso 2: Se requiere confirmación manual (Seguro)
      respuestaConcreta = "Deshabilitado";
      riesgo068 = "Bajo";
      comentario068 = "La carga automática de imágenes externas y enlaces se encuentra restringida. El sistema exige a los usuarios una confirmación manual antes de renderizar recursos externos en los correos, lo que previene el rastreo invisible y mitiga proactivamente los ataques de suplantación de identidad (phishing).";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Links & External Images Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo068}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario068: comentario068,
      riesgo068: riesgo068,
      score068: this.calcularScoreDeRiesgo(riesgo068)
    };
    }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo068: "Medio", score068: 2, comentario068: msg };
  }
}