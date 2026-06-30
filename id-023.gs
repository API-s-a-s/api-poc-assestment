/**
 * Estrategia para auditar el Programa de Protección Avanzada (APP - Titanium)
 * Utiliza la Admin SDK: Reports API (Activity Reports)
 * Implementa paginación masiva para extraer el historial completo de enrolamientos
 * y asegurar una auditoría estadística precisa.
 */
class UsuarioConfiguracionAvanzadaStrategy extends ApiStrategy {
  constructor() {
    // 1. Definimos la matriz con el ID-023 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-023", 
        valueKey: "valorPrincipal", // Entregará el número de usuarios únicos
        noteKey: "comentario023",
        riskKey: "riesgo023",
        scoreKey: "score023"
      }
    ];

    super("Advanced Protection Program (Titanium) Audit", configIDs);
    
    // Endpoint para buscar el historial de enrolamientos (blindaje Titanium)
    this.url = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?eventName=titanium_enroll";
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
      Logger.log(`[ERROR] APP (Titanium) Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR_API",
        riesgo023: "Medio",
        score023: 2,
        comentario023: `Error en la API Reports: ${json.error.message}. Impide contabilizar los eventos históricos de enrolamiento en el Programa de Protección Avanzada.`
      };
    }

    // 2. EXTRACCIÓN MASIVA (PAGINACIÓN OBLIGATORIA)
    // En el endpoint de activity de login, los registros vienen en el arreglo "items"
    let eventos = json.items || [];
    
    // Si la llamada inicial del Facade nos dejó páginas pendientes, re-hidratamos todo el historial
    if (json.nextPageToken) {
      Logger.log("[INFO] Paginación detectada. Extrayendo historial completo de eventos Titanium...");
      const todosLosEventos = this.fetchPaginated(this.url, "items");
      if (todosLosEventos) eventos = todosLosEventos;
    }
    
    // 3. LÓGICA DE NEGOCIO Y CÁLCULO ESTADÍSTICO
    // Usamos un Set para obtener la cantidad real de usuarios únicos blindados
    // (Previene conteos dobles si un usuario se enroló múltiples veces históricamente)
    const usuariosUnicos = new Set();

    eventos.forEach(evento => {
      if (evento.actor && evento.actor.email) {
        usuariosUnicos.add(evento.actor.email);
      }
    });

    const cantidadProtegidos = usuariosUnicos.size;

    // --- 4. APLICACIÓN DE MATRICES DE RIESGO ---
    let riesgo023, comentario023;

    if (cantidadProtegidos === 0) {
      // Caso 1: Nadie se ha registrado
      riesgo023 = "Medio"; // Riesgo "Medio" porque es un feature opcional extremo, pero altamente recomendado.
      comentario023 = "El registro de actividad del dominio no reporta eventos de enrolamiento; ningún usuario se encuentra inscrito en el Programa de Protección Avanzada (APP). Se recomienda evaluar este programa para blindar a los Super Administradores.";
    } else {
      // Caso 2: Hay al menos 1 usuario protegido
      riesgo023 = "Bajo";
      comentario023 = `CUMPLIMIENTO: Se identificaron exitosamente ${cantidadProtegidos} usuario(s) único(s) en el dominio que han completado su registro en el Programa de Protección Avanzada.`;
    }

    // Log informativo para la consola del auditor
    Logger.log(`[RESULTADO ID-023] Usuarios únicos con Protección Avanzada (Titanium): ${cantidadProtegidos} | Riesgo: ${riesgo023}`);

    // 5. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: { eventosAnalizados: eventos.length, metadata: "Data cruda omitida por tamaño" },
      valorPrincipal: cantidadProtegidos,
      comentario023: comentario023,
      riesgo023: riesgo023,
      score023: this.calcularScoreDeRiesgo(riesgo023)
    };
  }
}