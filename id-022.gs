/**
 * Estrategia para auditar los permisos de reserva de recursos e interoperabilidad con Exchange.
 * Evalúa los parámetros enable_exchange_room_booking y enable_full_event_details.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/calendar.interoperability
 */
class CalendarInteroperabilityStrategy extends ApiStrategy {
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
    const { policies, auth } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    // Filtramos las políticas pertenecientes a la interoperabilidad de Calendar
    let targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("calendar.interoperability")
    );
    
    Logger.log(`[ID-122] Se encontraron ${targetPolicies.length} políticas en memoria para este filtro.`);
    
    // Fallback híbrido: si no está en el bulk, consultar directamente a la API
    if (targetPolicies.length === 0 && auth) {
      Logger.log(`[ID-122] [WARNING] La API masiva no trajo configuraciones para esta política. Consultando API directamente...`);
      try {
        const adminEmail = auth.getCurrentUserEmail(); 
        const privilegedHeader = auth.getPrivilegedAuthHeader(adminEmail, [
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly"
        ]);

        const filter = `customer=="customers/${this.customerId}" && setting.type.matches(".*calendar.interoperability.*")`;
        const url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}&t=${new Date().getTime()}`;

        const options = {
          method: "get",
          headers: { ...privilegedHeader, "Cache-Control": "no-cache" }
        };

        const response = this.fetchWithBackoff(url, options);
        const json = JSON.parse(response.getContentText());
        targetPolicies = json.policies || [];
        Logger.log(`[ID-122] [SUCCESS] API directa retornó ${targetPolicies.length} políticas.`);
      } catch (e) {
        Logger.log(`[ID-122] Error al consultar la API directamente: ${e.message}`);
      }
    }

    if (targetPolicies.length > 0) {
      Logger.log(`[ID-122] Detalles de las políticas encontradas: ` + 
        JSON.stringify(targetPolicies.map(p => ({ 
          type: p.type, 
          name: p.name, 
          orgUnit: p.policyQuery?.orgUnit 
        })))
      );
    }
    
    let extractedBooking = null;
    let extractedFullDetails = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      // Resolvemos los conflictos utilizando el reductor por defecto
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "calendar.interoperability");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // Verificación resiliente para enable_exchange_room_booking
        if (valueNode.enable_exchange_room_booking !== undefined) {
          extractedBooking = valueNode.enable_exchange_room_booking;
        } else if (valueNode.enableExchangeRoomBooking !== undefined) {
          extractedBooking = valueNode.enableExchangeRoomBooking;
        }

        // Verificación resiliente para enable_full_event_details
        if (valueNode.enable_full_event_details !== undefined) {
          extractedFullDetails = valueNode.enable_full_event_details;
        } else if (valueNode.enableFullEventDetails !== undefined) {
          extractedFullDetails = valueNode.enableFullEventDetails;
        }
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Evaluamos la combinación de variables estrictas booleanas
    if (extractedBooking === true) {
      if (extractedFullDetails === true) {
        respuestaConcreta = "Activado (Detalles completos)";
        riesgo = "Medio";
        comentario = "La interoperabilidad con Exchange permite la reserva de recursos y expone los detalles completos de los eventos (títulos, descripciones, asistentes) a la infraestructura externa federada, incrementando la superficie de exposición de metadatos corporativos.";
      } else {
        respuestaConcreta = "Activado (Solo reserva/disponibilidad)";
        riesgo = "Bajo";
        comentario = "La reserva de recursos desde Exchange está habilitada pero se restringe la visibilidad de los detalles completos de los eventos. Protege la confidencialidad de la agenda mientras previene colisiones operativas en salas y equipos físicos.";
      }
    } else if (extractedBooking === false) {
      respuestaConcreta = "Desactivado";
      riesgo = "Bajo";
      comentario = "La reserva de recursos desde entornos externos de Exchange está desactivada de raíz. No existe exposición de metadatos de recursos ni de calendarios hacia plataformas externas mediante interoperabilidad federada.";
    } else {
      // Comportamiento predeterminado seguro del sistema
      respuestaConcreta = "Desactivado por defecto";
      riesgo = "Bajo";
      comentario = "No se encontraron políticas explícitas en la API para la interoperabilidad de calendarios. Google Workspace aplica el comportamiento predeterminado seguro, manteniendo deshabilitadas las conexiones externas de recursos.";
    }

    Logger.log(`[LOG] Calendar Resource Booking Interoperability Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Booking: ${extractedBooking} | FullDetails: ${extractedFullDetails}`);

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
    Logger.log(`[ID-122] ERROR: ${msg}`);
    return { 
      name: this.name, 
      valorPrincipal: "ERROR", 
      riesgo122: "Medio", 
      score122: 2, 
      comentario122: msg 
    };
  }
}