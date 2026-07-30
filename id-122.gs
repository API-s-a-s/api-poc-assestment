/**
 * Estrategia para auditar los permisos de reserva de recursos e interoperabilidad con Exchange.
 * Evalúa los parámetros enable_exchange_room_booking y enable_full_event_details.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/calendar.interoperability
 */
class CalendarInteroperability extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-122", 
        valueKey: "valorPrincipal",
        noteKey: "comentario122",
        riskKey: "riesgo122",
        scoreKey: "score122"
      }
    ];

    super("Calendar Resource Booking Interoperability Audit", configIDs);
    this.category = "Servicios adicionales";
    this.customerId = customerId;
    this.settingType = "settings/calendar.interoperability";
  }

  /**
   * Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico.
   */
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  evaluateInMemory(globalContext) {
    const { policies, auth } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global de políticas.");

    Logger.log(`[DEBUG ID-122] ==================================================`);
    Logger.log(`[DEBUG ID-122] Total de políticas recibidas en memoria global: ${policies.length}`);

    // 1. Filtrado de políticas en memoria RAM utilizando el sufijo flexible
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("calendar.interoperability")
    );
    
    Logger.log(`[DEBUG ID-122] Se encontraron ${targetPolicies.length} políticas en memoria RAM con tipo '${this.settingType}'.`);
    
    // Inspección preventiva: si viene vacío en memoria, ver qué tipos de Calendar sí existen
    if (targetPolicies.length === 0) {
      const calendarTypes = policies
        .map(p => p.setting && p.setting.type)
        .filter(t => t && t.toLowerCase().includes("calendar"));
      Logger.log(`[DEBUG ID-122] [ALERT] Filtro en memoria vacío. Tipos de 'calendar' detectados en la carga masiva: ${JSON.stringify(calendarTypes)}`);
    }
    
    // 2. Consulta de contingencia directa a la API si el lienzo masivo no contiene la política
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[DEBUG ID-122] [WARNING] Sin políticas en memoria. Iniciando consulta directa HTTP a Cloud Identity API...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*calendar.interoperability.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        Logger.log(`[DEBUG ID-122] URL generada para API directa: ${url}`);
        Logger.log(`[DEBUG ID-122] Filtro CEL enviado: ${filter}`);

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" },
          muteHttpExceptions: true
        };

        const response = this.fetchWithBackoff(url, options);
        const statusCode = response.getResponseCode();
        const responseText = response.getContentText();

        Logger.log(`[DEBUG ID-122] Código de Respuesta HTTP Directa: ${statusCode}`);
        Logger.log(`[DEBUG ID-122] RAW Response Body Directa: ${responseText}`);

        if (statusCode === 200) {
          const json = JSON.parse(responseText);
          targetPolicies = json.policies || [];
          Logger.log(`[DEBUG ID-122] [SUCCESS] La consulta directa recuperó ${targetPolicies.length} políticas.`);
        } else {
          Logger.log(`[DEBUG ID-122] [ERROR] La API denegó o falló con código HTTP ${statusCode}`);
        }
      } catch (e) {
        Logger.log(`[DEBUG ID-122] Excepción en transporte HTTP directo: ${e.message}`);
      }
    }

    let extractedBooking = null;
    let extractedFullDetails = null;
    let rawData = null;
    let isDefaultState = false;

    // 3. Extracción de parámetros desde política explícita o hidratación con valores por defecto
    if (targetPolicies.length > 0) {
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "calendar.interoperability");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        Logger.log(`[DEBUG ID-122] Estructura completa de rootPolicy.setting: ${JSON.stringify(rootPolicy.setting)}`);

        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        Logger.log(`[DEBUG ID-122] Estructura interna de valueNode: ${JSON.stringify(valueNode)}`);
        
        // Extracción resiliente de campos
        if (valueNode.enable_exchange_room_booking !== undefined) {
          extractedBooking = valueNode.enable_exchange_room_booking;
        } else if (valueNode.enableExchangeRoomBooking !== undefined) {
          extractedBooking = valueNode.enableExchangeRoomBooking;
        }

        if (valueNode.enable_full_event_details !== undefined) {
          extractedFullDetails = valueNode.enable_full_event_details;
        } else if (valueNode.enableFullEventDetails !== undefined) {
          extractedFullDetails = valueNode.enableFullEventDetails;
        }
      }
    } else {
      // Hidratación sintética cuando la API no contiene objetos (Sparse Storage / Estado por defecto de fábrica)
      isDefaultState = true;
      const defaultValues = DefaultPolicyValuesRegistry.getDefaults(this.settingType) || {
        enable_exchange_room_booking: false,
        enable_full_event_details: false
      };
      
      extractedBooking = defaultValues.enable_exchange_room_booking;
      extractedFullDetails = defaultValues.enable_full_event_details;
      
      rawData = {
        type: "SYSTEM_DEFAULT_HYDRATED",
        setting: {
          type: this.settingType,
          value: defaultValues
        }
      };
      Logger.log(`[DEBUG ID-122] [INFO] Sin políticas explícitas. Se hidrató con valores predeterminados de fábrica: enable_exchange_room_booking=${extractedBooking}, enable_full_event_details=${extractedFullDetails}`);
    }

    Logger.log(`[DEBUG ID-122] Valores extraídos finales -> enable_exchange_room_booking: ${extractedBooking} | enable_full_event_details: ${extractedFullDetails} | EsPredeterminado: ${isDefaultState}`);

    let respuestaConcreta, riesgo, comentario;

    // 4. Evaluación de combinaciones lógicas de seguridad
    if (extractedBooking === true) {
      if (extractedFullDetails === true) {
        respuestaConcreta = "Activado (Detalles completos)";
        riesgo = "Medio";
        comentario = "La interoperabilidad con Exchange permite la reserva de recursos y expone los detalles completos de los eventos (títulos, descripciones, asistentes) a la infraestructura externa federada, incrementando la superficie de exposición de metadatos corporativos.";
        Logger.log(`[DEBUG ID-122] Rama tomada: Booking=true, FullDetails=true -> Riesgo Medio`);
      } else {
        respuestaConcreta = "Habilitado";
        riesgo = "Bajo";
        comentario = "La reserva de recursos está habilitada pero se restringe la visibilidad de los detalles completos de los eventos.";
        Logger.log(`[DEBUG ID-122] Rama tomada: Booking=true, FullDetails=false -> Riesgo Bajo`);
      }
    } else if (extractedBooking === false) {
      respuestaConcreta = isDefaultState ? "Deshabilitado por defecto" : "Deshabilitado";
      riesgo = "Bajo";
      comentario = isDefaultState 
        ? "Google Workspace aplica el comportamiento predeterminado seguro, manteniendo deshabilitadas las conexiones externas de recursos"
        : "La reserva de recursos desde entornos externos está desactivada.";
      Logger.log(`[DEBUG ID-122] Rama tomada: Booking=false -> Riesgo Bajo`);
    } else {
      respuestaConcreta = "revisión manual";
      riesgo = "";
      comentario = "";
    }

    Logger.log(`[DEBUG ID-122] Resultado final a guardar -> Valor: '${respuestaConcreta}' | Riesgo: '${riesgo}' | Score: ${this.calcularScoreDeRiesgo(riesgo)}`);


    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario122: comentario,
      riesgo122: riesgo,
      score122: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[DEBUG ID-122] [ERROR CRÍTICO]: ${msg}`);
    return { 
      name: this.name, 
      valorPrincipal: "ERROR", 
      riesgo122: "Medio", 
      score122: 2, 
      comentario122: msg 
    };
  }
}