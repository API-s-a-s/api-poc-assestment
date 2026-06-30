/**
 * Estrategia para auditar la seguridad (escaneo) de enlaces e imágenes externas en Gmail.
 * Evalúa si el sistema escanea activamente URLs acortadas o incrustadas en busca de amenazas.
 */
class GmailLinksExternalImagesSecurityStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Matriz de configuración para ID-071
    const configIDs = [
      { 
        id: "ID-071", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario071",
        riskKey: "riesgo071",
        scoreKey: "score071"
      }
    ];

    super("Gmail Links and External Images Security Audit", configIDs);
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

    let isScanningEnabled = false;
    let rawData = null;

    if (gmailPolicies.length === 0) {
      // Por defecto, asumimos que el escaneo no está habilitado
      isScanningEnabled = false;
    } else {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(gmailPolicies, "gmail.links_and_external_images");
      if (rootPolicy && rootPolicy.setting) {
        Logger.log(`[DEBUG ID-071] rootPolicy: ${JSON.stringify(rootPolicy.setting)}`);
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-071] valueNode: ${JSON.stringify(valueNode)}`);
        
        if (valueNode.enableExternalImageScanning === true || 
            (valueNode.state && valueNode.state.toUpperCase() === 'ENABLED')) {
          isScanningEnabled = true;
        }
      }
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo071, comentario071;

    if (isScanningEnabled) {
      // Caso 1: Escaneo de seguridad habilitado (Seguro)
      respuestaConcreta = "Habilitado";
      riesgo071 = "Bajo";
      comentario071 = "El escaneo de seguridad para enlaces e imágenes externas se encuentra habilitado. El entorno de Google Workspace inspecciona activamente las URLs incrustadas y los enlaces acortados para identificar y bloquear amenazas antes de que el usuario interactúe con ellos, mitigando riesgos de phishing y malware.";
    } else {
      // Caso 2: Escaneo de seguridad deshabilitado (Riesgo Alto por phishing)
      respuestaConcreta = "Deshabilitado";
      riesgo071 = "Alto";
      comentario071 = "El escaneo de seguridad en enlaces e imágenes se encuentra deshabilitado. Esta configuración expone a los usuarios a riesgos críticos, ya que permite que URLs maliciosas o acortadores engañosos lleguen a la bandeja de entrada sin ser evaluados por los motores de Safe Browsing, facilitando ataques de suplantación de identidad.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Links & External Images Security Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo071}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario071: comentario071,
      riesgo071: riesgo071,
      score071: this.calcularScoreDeRiesgo(riesgo071)
    };
    }

  _buildErrorResponse(msg) {
    return { name: this.name, valorPrincipal: "ERROR", riesgo071: "Medio", score071: 2, comentario071: msg };
  }
}