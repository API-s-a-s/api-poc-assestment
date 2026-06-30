/**
 * Estrategia para auditar la configuración del registro SPF (Sender Policy Framework).
 * Realiza una consulta DNS pública para validar si el dominio está protegido contra suplantación.
 * Utiliza Google Public DNS API
 */
class SpfRecordAuditStrategy extends ApiStrategy {
  /**
   * @param {string} domain - El dominio principal a auditar (ej. "midominio.com")
   */
  constructor(domain) {
    // 1. Matriz de configuración para ID-057
    const configIDs = [
      { 
        id: "ID-057", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario057",
        riskKey: "riesgo057",
        scoreKey: "score057"
      }
    ];

    super("SPF Record DNS Audit", configIDs);
    
    // Endpoint de Google Public DNS para consultar registros TXT (tipo 16)
    this.url = `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=TXT`;
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
    // La API DNS de Google devuelve Status: 0 si fue exitoso. Otros códigos (ej. 3 para NXDOMAIN) indican problemas.
    if (json.error || (json.Status !== 0 && json.Status !== 3)) {
      Logger.log(`[ERROR] SPF Audit: Fallo al consultar el DNS. Detalles: ${JSON.stringify(json)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo057: "Medio",
        score057: 2,
        comentario057: "Error de conectividad al consultar los servidores DNS públicos de Google. No fue posible auditar el registro SPF del dominio."
      };
    }

    let spfRecord = null;
    let isSpfSecure = false;

    // 2. PARSEO DE REGISTROS DNS
    if (json.Answer && json.Answer.length > 0) {
      json.Answer.forEach(record => {
        // Los registros TXT vienen en la propiedad 'data'
        const recordData = (record.data || "").toLowerCase();
        
        // Buscamos específicamente el que declare la política SPF
        if (recordData.includes("v=spf1")) {
          spfRecord = recordData;
          
          // Validamos si es restrictivo (~all o -all). 
          // Si termina en +all (muy peligroso) o no define restricción, se considera inseguro.
          if (spfRecord.includes("-all") || spfRecord.includes("~all")) {
            isSpfSecure = true;
          }
        }
      });
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo057, comentario057;

    if (spfRecord && isSpfSecure) {
      // Caso 1: SPF existe y está bien configurado (Seguro)
      respuestaConcreta = "Habilitado";
      riesgo057 = "Bajo";
      comentario057 = `El dominio cuenta con un registro SPF válido y restrictivo configurado en su zona DNS (${spfRecord}). Esto protege la reputación del dominio al impedir que servidores no autorizados envíen correos electrónicos fraudulentos a nombre de la organización.`;
    } else if (spfRecord && !isSpfSecure) {
      // Caso 2: SPF existe pero es permisivo (+all) (Riesgo Alto)
      respuestaConcreta = "Deshabilitado";
      riesgo057 = "Alto";
      comentario057 = `Se detectó un registro SPF (${spfRecord}), pero se encuentra configurado de manera excesivamente permisiva (ej. terminación '+all' o falta de restricción final). Esto representa una vulnerabilidad crítica, ya que autoriza explícitamente a cualquier servidor en internet a enviar correos a nombre del dominio.`;
    } else {
      // Caso 3: No hay SPF (Riesgo Alto)
      respuestaConcreta = "Deshabilitado";
      riesgo057 = "Alto";
      comentario057 = "No se detectó ningún registro SPF (Sender Policy Framework) en la zona DNS pública del dominio. Esta es una falla crítica de autenticación que facilita la suplantación de identidad (Spoofing) y provoca que los correos legítimos enviados por la organización sean clasificados como Spam por los destinatarios.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] SPF Audit: Resultado -> ${respuestaConcreta}. Registro encontrado: ${spfRecord || 'Ninguno'} | Riesgo: ${riesgo057}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario057: comentario057,
      riesgo057: riesgo057,
      score057: this.calcularScoreDeRiesgo(riesgo057)
    };
  }
}