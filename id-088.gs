/**
 * Estrategia para auditar la configuración del registro MTA-STS (Cifrado TLS estricto).
 * Realiza una consulta DNS pública para validar si el dominio exige conexiones cifradas para el tránsito de correos.
 * Utiliza Google Public DNS API 
 */
class MtaStsRecordAuditStrategy extends ApiStrategy {
  /**
   * @param {string} domain - El dominio principal a auditar (ej. "midominio.com")
   */
  constructor(domain) {
    // 1. Matriz de configuración para ID-088
    const configIDs = [
      { 
        id: "ID-088", 
        valueKey: "valorPrincipal", // Retornará "Habilitado" o "Deshabilitado"
        noteKey: "comentario088",
        riskKey: "riesgo088",
        scoreKey: "score088"
      }
    ];

    super("MTA-STS Record DNS Audit", configIDs);
    
    // Endpoint de Google Public DNS. El registro siempre vive en el subdominio _mta-sts
    const mtaStsSelector = `_mta-sts.${domain}`;
    this.url = `https://dns.google/resolve?name=${encodeURIComponent(mtaStsSelector)}&type=TXT`;
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
      Logger.log(`[ERROR] MTA-STS Audit: Fallo al consultar el DNS. Detalles: ${JSON.stringify(json)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo088: "Medio",
        score088: 2,
        comentario088: "Error de conectividad al consultar los servidores DNS públicos de Google. No fue posible auditar el registro MTA-STS del dominio."
      };
    }

    let mtaStsRecord = null;
    let isMtaStsEnabled = false;

    // 2. PARSEO DE REGISTROS DNS
    if (json.Answer && json.Answer.length > 0) {
      json.Answer.forEach(record => {
        // Extraemos el texto del registro TXT
        const recordData = (record.data || "").toLowerCase();
        
        // Un registro MTA-STS válido debe comenzar declarando el protocolo v=STSv1
        if (recordData.includes("v=stsv1")) {
          mtaStsRecord = recordData;
          isMtaStsEnabled = true;
        }
      });
    }

    // --- 3. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO INFERIDAS ---
    let respuestaConcreta;
    let riesgo088, comentario088;

    if (isMtaStsEnabled) {
      // Caso 1: MTA-STS activo (Seguro)
      respuestaConcreta = "Habilitado";
      riesgo088 = "Bajo";
      comentario088 = `El dominio cuenta con un registro MTA-STS válido (${mtaStsRecord}). Esto garantiza que los servidores de correo externos estén obligados a usar conexiones cifradas (TLS) y validar el certificado de Google Workspace antes de transferir mensajes, mitigando ataques de interceptación (Man-in-the-Middle).`;
    } else {
      // Caso 2: No hay MTA-STS (Riesgo Medio)
      respuestaConcreta = "Deshabilitado";
      riesgo088 = "Medio";
      comentario088 = "No se detectó un registro MTA-STS en el dominio. El tránsito de correos electrónicos dependerá del cifrado 'oportunista', lo que significa que si un atacante interfiere la red, la conexión podría degradarse a texto plano, exponiendo el contenido de los mensajes en tránsito.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] MTA-STS Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo088}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario088: comentario088,
      riesgo088: riesgo088,
      score088: this.calcularScoreDeRiesgo(riesgo088)
    };
  }
}