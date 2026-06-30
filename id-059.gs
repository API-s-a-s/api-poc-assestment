/**
 * Estrategia para auditar la configuración del registro DMARC.
 * Realiza una consulta DNS pública para validar si existe una política contra la suplantación de identidad.
 * Utiliza Google Public DNS API (Gratuita y sin autenticación)
 * Desarrollada con lógica de negocio y comentarios inyectados para el ID-059.
 */
class DmarcRecordAuditStrategy extends ApiStrategy {
  /**
   * @param {string} domain - El dominio principal a auditar (ej. "midominio.com")
   */
  constructor(domain) {
    // 1. Matriz de configuración para ID-059
    const configIDs = [
      { 
        id: "ID-059", 
        valueKey: "valorPrincipal", // Retornará el estado del DMARC
        noteKey: "comentario059",
        riskKey: "riesgo059",
        scoreKey: "score059"
      }
    ];

    super("DMARC Record DNS Audit", configIDs);
    
    // Endpoint de Google Public DNS. El registro DMARC siempre vive en el subdominio _dmarc
    const dmarcSelector = `_dmarc.${domain}`;
    this.url = `https://dns.google/resolve?name=${encodeURIComponent(dmarcSelector)}&type=TXT`;
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
    if (json.error || (json.Status !== 0 && json.Status !== 3)) {
      Logger.log(`[ERROR] DMARC Audit: Fallo al consultar el DNS. Detalles: ${JSON.stringify(json)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo059: "Medio",
        score059: 2,
        comentario059: "Error de conectividad al consultar los servidores DNS públicos de Google. No fue posible auditar el registro DMARC del dominio."
      };
    }

    let dmarcRecord = null;
    let dmarcPolicy = null;

    // 2. PARSEO DE REGISTROS DNS
    if (json.Answer && json.Answer.length > 0) {
      json.Answer.forEach(record => {
        // Extraemos el texto del registro TXT
        const recordData = (record.data || "").toLowerCase();
        
        // Un registro DMARC válido debe comenzar declarando el protocolo v=DMARC1
        if (recordData.includes("v=dmarc1")) {
          dmarcRecord = recordData;
          
          // Evaluamos la política (p=) aplicada
          if (recordData.includes("p=reject")) {
            dmarcPolicy = "reject";
          } else if (recordData.includes("p=quarantine")) {
            dmarcPolicy = "quarantine";
          } else if (recordData.includes("p=none")) {
            dmarcPolicy = "none";
          }
        }
      });
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo059, comentario059;

    if (dmarcRecord && (dmarcPolicy === "reject" || dmarcPolicy === "quarantine")) {
      // Caso 1: DMARC activo y bloqueando (Seguro)
      respuestaConcreta = "Habilitado (Estricto)";
      riesgo059 = "Bajo";
      comentario059 = `El dominio cuenta con un registro DMARC válido y restrictivo (política '${dmarcPolicy}'). Esta configuración protege activamente el dominio, instruyendo a los servidores receptores en internet a rechazar o enviar a spam cualquier correo fraudulento que intente suplantar a la organización.`;
    } else if (dmarcRecord && dmarcPolicy === "none") {
      // Caso 2: DMARC en modo monitoreo (Riesgo Medio)
      respuestaConcreta = "Habilitado (Monitoreo)";
      riesgo059 = "Medio";
      comentario059 = "El dominio tiene un registro DMARC, pero se encuentra en modo de solo monitoreo (p=none). Aunque permite recolectar métricas de autenticación, no detiene la entrega de correos fraudulentos, dejando a la organización vulnerable ante ataques de suplantación.";
    } else {
      // Caso 3: No hay DMARC o está mal configurado (Riesgo Alto)
      respuestaConcreta = "Deshabilitado";
      riesgo059 = "Alto";
      comentario059 = "No se detectó ningún registro DMARC válido en el DNS. El dominio carece por completo de políticas de protección contra el spoofing, lo que permite que actores maliciosos envíen libremente campañas de phishing haciéndose pasar por la organización.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] DMARC Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo059}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario059: comentario059,
      riesgo059: riesgo059,
      score059: this.calcularScoreDeRiesgo(riesgo059)
    };
  }
}