/**
 * Estrategia para auditar el SLA de desaprovisionamiento oportuno.
 * Utiliza la Admin SDK: Reports API (Audit Activity)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-031
 */
class SlaOffboardingAuditStrategy extends ApiStrategy {
  constructor() {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-031 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-031", 
        valueKey: "valorPrincipal", // Entregará "Habilitado" o "Deshabilitado"
        noteKey: "comentario031",
        riskKey: "riesgo031",
        scoreKey: "score031"
      }
    ];

    super("SLA Offboarding Audit", configIDs);
    
    // Consultamos los eventos de auditoría de la consola de administración
    this.url = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin?eventName=SUSPEND_USER";
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
      Logger.log(`[ERROR] SLA Offboarding Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo031: "Medio",
        score031: 2,
        comentario031: "Error de lectura o permisos insuficientes en la API Reports que impide consultar los registros de auditoría asociados a la suspensión de cuentas de usuario."
      };
    }

    const eventos = json.items || [];
    
    // --- 2. LÓGICA DE SALIDA ESTANDARIZADA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo031, comentario031;

    if (eventos.length > 0) {
      respuestaConcreta = "Habilitado";
      riesgo031 = "Bajo";
      
      const ultimoEvento = eventos[0];
      let targetUser = "Desconocido";
      let fechaSuspension = "Fecha desconocida";
      
      if (ultimoEvento && ultimoEvento.id && ultimoEvento.id.time) {
        fechaSuspension = new Date(ultimoEvento.id.time).toLocaleDateString();
        if (ultimoEvento.events && ultimoEvento.events[0] && ultimoEvento.events[0].parameters) {
          const targetUserParam = ultimoEvento.events[0].parameters.find(p => p.name === "USER_EMAIL");
          if (targetUserParam) targetUser = targetUserParam.value;
        }
        Logger.log(`[LOG] SLA Offboarding: Última suspensión registrada -> ${targetUser} el ${fechaSuspension}. Riesgo: ${riesgo031}`);
      }
      comentario031 = `Trazabilidad Activa: Existen registros recientes (Última baja: ${fechaSuspension} para el usuario ${targetUser}) que documentan la suspensión de cuentas, permitiendo medir el SLA.`;
    } else {
      respuestaConcreta = "Deshabilitado";
      riesgo031 = "Alto";
      comentario031 = "La bitácora no contiene registros de suspensión de cuentas.";
      Logger.log(`[LOG] SLA Offboarding: No se encontraron eventos de suspensión recientes en el log de auditoría. Riesgo: ${riesgo031}`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario031: comentario031,
      riesgo031: riesgo031,
      score031: this.calcularScoreDeRiesgo(riesgo031)
    };
  }
}