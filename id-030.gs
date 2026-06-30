/**
 * Estrategia para auditar el proceso de desaprovisionamiento (Offboarding)
 * Utiliza la Admin SDK: Directory API para evaluar motivos de suspensión
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-030
 */
class DeprovisioningAuditStrategy extends ApiStrategy {
  constructor() {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-030 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-030",
        valueKey: "valorPrincipal", // Entregará "Habilitado" o "Deshabilitado"
        noteKey: "comentario030",
        riskKey: "riesgo030",
        scoreKey: "score030"
      }
    ];

    super("Account Deprovisioning Audit", configIDs);
    
    // Escaneamos el directorio para buscar cómo se manejan las bajas
    this.url = "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=500";
    this.category = "Identidad y autenticación";
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
    // 1. EVALUACIÓN EN CASO DE ERROR DE API
    if (json.error) {
      Logger.log(`[ERROR] Deprovisioning Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo030: "Medio",
        score030: 2,
        comentario030: "Error de lectura o permisos insuficientes en la API Directory que impide extraer el directorio y auditar el estado y motivo de suspensión de los usuarios."
      };
    }

    let usuarios = json.users || [];

    if (json.nextPageToken) {
       const paginados = this.fetchPaginated(this.url, "users");
       if (paginados) usuarios = paginados;
    }

    // Usamos .filter() para encontrar rápidamente a los usuarios suspendidos por un administrador
    const suspendidosAdmin = usuarios.filter(usuario => 
      usuario.suspended === true && usuario.suspensionReason === 'ADMIN'
    );

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo030, comentario030;

    if (suspendidosAdmin.length > 0) {
      respuestaConcreta = "Habilitado";
      riesgo030 = "Bajo";
      comentario030 = "Existen cuentas retenidas en estado de suspensión administrativa (ADMIN).";
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo030 = "Medio";
      comentario030 = "No se detectaron cuentas suspendidas administrativamente.";
    }

    // Log informativo para el auditor en la consola
    Logger.log(`[LOG] Deprovisioning Audit: Se detectaron ${suspendidosAdmin.length} cuentas suspendidas administrativamente. Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo030}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario030: comentario030,
      riesgo030: riesgo030,
      score030: this.calcularScoreDeRiesgo(riesgo030)
    };
  }
}