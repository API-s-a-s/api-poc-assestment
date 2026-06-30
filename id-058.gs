/**
 * Estrategia para auditar la configuración del registro DKIM (DomainKeys Identified Mail).
 * Realiza una consulta DNS pública para validar si los correos del dominio están firmados criptográficamente.
 * Utiliza Google Public DNS API (Gratuita y sin autenticación)
 * Desarrollada con lógica de negocio y comentarios inyectados para el ID-058.
 */
class DkimRecordAuditStrategy extends ApiStrategy {
  /**
   * @param {string} domain - El dominio principal a auditar (ej. "midominio.com")
   */
  constructor(domain) {
    // 1. Matriz de configuración para ID-058
    const configIDs = [
      { 
        id: "ID-058", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario058",
        riskKey: "riesgo058",
        scoreKey: "score058"
      }
    ];

    super("DKIM Record DNS Audit", configIDs);
    
    // Endpoint de Google Public DNS. Para Workspace, el selector por defecto es 'google'
    const dkimSelector = `google._domainkey.${domain}`;
    this.url = `https://dns.google/resolve?name=${encodeURIComponent(dkimSelector)}&type=TXT`;
    this.category = "Email y DNS";
  }

  getRequestConfig() {
    return {
      url: this.url,
      method: "get",
      muteHttpExceptions: true
    };
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

  parseResponse(json) {
    // 1. EVALUACIÓN EN CASO DE ERROR DE RED O API
    // Status 0 = Éxito. Status 3 = NXDOMAIN (No existe el registro, lo cual manejaremos más abajo).
    if (json.error || (json.Status !== 0 && json.Status !== 3)) {
      Logger.log(`[ERROR] DKIM Audit: Fallo al consultar el DNS. Detalles: ${JSON.stringify(json)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo058: "Medio",
        score058: 2,
        comentario058: "Error de conectividad al consultar los servidores DNS públicos de Google. No fue posible auditar el registro DKIM del dominio."
      };
    }

    let dkimRecord = null;
    let isDkimSecure = false;

    // 2. PARSEO DE REGISTROS DNS
    if (json.Answer && json.Answer.length > 0) {
      json.Answer.forEach(record => {
        // Los registros TXT vienen en la propiedad 'data'
        const recordData = (record.data || ""); // No lo pasamos a minúsculas porque las llaves base64 son sensibles a mayúsculas
        
        // Buscamos específicamente que declare la versión de DKIM y tenga una llave pública 'p='
        if (recordData.includes("v=DKIM1") && recordData.includes("p=")) {
          dkimRecord = recordData;
          isDkimSecure = true;
        }
      });
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo058, comentario058;

    if (dkimRecord && isDkimSecure) {
      // Caso 1: DKIM existe y está bien configurado (Seguro)
      respuestaConcreta = "Habilitado";
      riesgo058 = "Bajo";
      comentario058 = "El dominio cuenta con un registro DKIM (DomainKeys Identified Mail) válido y activo. Los correos salientes se están firmando criptográficamente, lo que asegura su integridad en tránsito y mejora drásticamente la tasa de entrega legítima en los servidores de destino.";
    } else {
      // Caso 2: No hay DKIM o está mal configurado (Riesgo Alto)
      respuestaConcreta = "Deshabilitado";
      riesgo058 = "Alto";
      comentario058 = "No se detectó una llave pública DKIM válida en el selector por defecto de Google Workspace ('google._domainkey'). Esta es una falla grave de autenticación; los correos saldrán sin firma criptográfica, lo que aumenta la probabilidad de ser bloqueados o marcados como Spam por los destinatarios.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] DKIM Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo058}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario058: comentario058,
      riesgo058: riesgo058,
      score058: this.calcularScoreDeRiesgo(riesgo058)
    };
  }
}