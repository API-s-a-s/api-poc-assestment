/**
 * Estrategia para auditar la procedencia del aprovisionamiento de usuarios (ID-029).
 * Interroga los registros inmutables de la Admin SDK Reports API (aplicación 'admin')
 * para diferenciar las creaciones manuales de las automatizadas según el tipo de actor iniciador.
 */
class ManualUserAuditStrategy extends ApiStrategy {
  constructor() {
    // 1. Definimos la matriz con el ID-029 y todas sus llaves para el mapeo polimórfico
    const configIDs = [
      { 
        id: "ID-029", 
        valueKey: "valorPrincipal", // Retornará la relación exacta (Ej: "2 manuales / 48 automáticas")
        noteKey: "comentario029",
        riskKey: "riesgo029",
        scoreKey: "score029"
      }
    ];

    super("Manual User Creation Audit", configIDs);

    // 2. CORRECCIÓN ARQUITECTÓNICA: Endpoint de auditoría de la aplicación Admin (Reports API)
    // Buscamos específicamente el evento inmutable 'CREATE_USER'
    this.url = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin?eventName=CREATE_USER";
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
    // 1. EVALUACIÓN DEFENSIVA EN CASO DE ERROR DE API
    if (json.error) {
      Logger.log(`[ERROR API] Manual User Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR_API",
        riesgo029: "Medio",
        score029: 2,
        comentario029: `Error de lectura en la API Reports (Admin application): ${json.error.message}. Impide cuantificar el origen del aprovisionamiento.`
      };
    }

    // 2. EXTRACCIÓN MASIVA E HISTÓRICA (PAGINACIÓN OBLIGATORIA)
    let eventos = json.items || [];

    // Si existen más páginas de bitácoras administrativas, re-hidratamos todo el bloque usando el paginador del padre
    if (json.nextPageToken) {
      Logger.log("[INFO] Paginación detectada en logs de administración. Extrayendo historial completo...");
      const todosLosEventos = this.fetchPaginated(this.url, "items");
      if (todosLosEventos) eventos = todosLosEventos;
    }

    // Sets de control para asegurar la unicidad criptográfica de las cuentas creadas
    const creadosManualmente = new Set();
    const creadosAutomatizados = new Set();

    // 3. LÓGICA DE CLASIFICACIÓN POR ACTOR INICIADOR
    eventos.forEach(item => {
      const actorEmail = (item.actor && item.actor.email) ? item.actor.email.toLowerCase().trim() : "";
      
      // Localizamos el parámetro del usuario que fue creado (USER_EMAIL) dentro del log estructurado
      let usuarioCreado = "";
      if (item.events && item.events.length > 0) {
        const parametros = item.events[0].parameters || [];
        const paramUsuario = parametros.find(p => p.name === "USER_EMAIL");
        if (paramUsuario && paramUsuario.value) {
          usuarioCreado = paramUsuario.value.toLowerCase().trim();
        }
      }

      // Fallback seguro en caso de que el esquema del log varíe: usamos el id único de la transacción
      if (!usuarioCreado) {
        usuarioCreado = (item.id && item.id.uniqueQualifier) ? item.id.uniqueQualifier : Utilities.getUuid();
      }

      // Evaluación del origen basándonos en los atributos del actor (Cuenta de servicio vs Humano)
      if (actorEmail.includes("gserviceaccount.com") || actorEmail.includes("automation") || actorEmail.includes("sync")) {
        creadosAutomatizados.add(usuarioCreado);
      } else {
        creadosManualmente.add(usuarioCreado);
      }
    });

    const totalManuales = creadosManualmente.size;
    const totalAutomatizados = creadosAutomatizados.size;
    const totalAltas = totalManuales + totalAutomatizados;

    const respuestaConcreta = `${totalManuales} manuales / ${totalAutomatizados} automáticas`;

    // --- 4. APLICACIÓN DE MATRICES DE RIESGO DE GOBERNANZA ---
    let riesgo029, comentario029;

    if (totalAltas === 0) {
      riesgo029 = "Bajo";
      comentario029 = "No se detectaron eventos de creación de usuarios.";
    } else if (totalManuales === 0) {
      riesgo029 = "Bajo";
      comentario029 = "El 100% de las altas de usuarios en el periodo auditado se realizaron a través de flujos automatizados (Cuentas de servicio o IdP).";
    } else {
      riesgo029 = "Medio";
      comentario029 = `Se detectaron ${totalManuales} cuentas creadas manualmente desde la consola web.`;
    }

    // Log informativo detallado en la consola del desarrollador
    Logger.log(`[RESULTADO ID-029] Auditoría de Altas: ${respuestaConcreta} | Riesgo: ${riesgo029}`);

    // 5. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      // Retornamos un resumen numérico para no desbordar la memoria de Sheets con strings kilométricos
      raw: { totalEventosProcesados: eventos.length, resumenConteo: respuestaConcreta },
      valorPrincipal: respuestaConcreta,
      comentario029: comentario029,
      riesgo029: riesgo029,
      score029: this.calcularScoreDeRiesgo(riesgo029)
    };
  }
}