/**
 * Estrategia para auditar las opciones de uso compartido externo para calendarios secundarios.
 * Evalúa el parámetro max_allowed_external_sharing.
 * Utiliza Cloud Identity Policy API (v1).
 * setting.type: settings/calendar.secondary_calendar_max_allowed_external_sharing
 */
class CalendarSecondaryExternalSharingStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-120", 
        valueKey: "valorPrincipal",
        noteKey: "comentario120",
        riskKey: "riesgo120",
        scoreKey: "score120"
      }
    ];

    super("Calendar Secondary External Sharing Audit", configIDs);
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
    const { policies } = globalContext;
    if (!policies) return this._buildErrorResponse("Falta el contexto global.");

    // Filtramos las políticas pertenecientes al sub-entorno de Calendar (uso compartido externo de calendarios secundarios)
    const targetPolicies = policies.filter(p => 
      p.setting && (p.setting.type || "").endsWith("calendar.secondary_calendar_max_allowed_external_sharing")
    );
    
    Logger.log(`[ID-120] Se encontraron ${targetPolicies.length} políticas en memoria para este filtro.`);
    if (targetPolicies.length > 0) {
      Logger.log(`[ID-120] Detalles de las políticas encontradas: ` + 
        JSON.stringify(targetPolicies.map(p => ({ 
          type: p.type, 
          name: p.name, 
          sortOrder: p.policyQuery?.sortOrder, 
          hasGroup: !!p.policyQuery?.group, 
          orgUnit: p.policyQuery?.orgUnit 
        })))
      );
    } else {
      Logger.log(`[ID-120] [WARNING] La API masiva no trajo configuraciones para esta política. Esto puede explicar el retorno NULL o valores por defecto.`);
    }
    
    let extractedValue = null;
    let rawData = null;

    if (targetPolicies.length > 0) {
      // Resolvemos los conflictos utilizando el reductor por defecto (Max)
      const rootPolicy = PolicyReducerFactory.getEffectiveRootPolicy(targetPolicies, "calendar.secondary_calendar_max_allowed_external_sharing");
      if (rootPolicy && rootPolicy.setting) {
        rawData = rootPolicy;
        const valueNode = rootPolicy.setting.value || rootPolicy.setting;
        
        // Verificación resiliente soportando variantes de nomenclatura
        if (valueNode.max_allowed_external_sharing !== undefined) {
            extractedValue = valueNode.max_allowed_external_sharing;
        } else if (valueNode.maxAllowedExternalSharing !== undefined) {
            extractedValue = valueNode.maxAllowedExternalSharing;
        }
      }
    }

    let respuestaConcreta, riesgo, comentario;

    // Evaluamos el enum de max_allowed_external_sharing para calendarios secundarios
    if (extractedValue === "EXTERNAL_FREE_BUSY_ONLY") {
      respuestaConcreta = "Sólo libre/ocupado";
      riesgo = "Bajo";
      comentario = "La configuración limita el uso compartido externo de los calendarios secundarios únicamente a la disponibilidad de tiempo libre u ocupado. No se exponen detalles de los eventos ni asistentes.";
    } else if (extractedValue === "EXTERNAL_ALL_INFO_READ_ONLY") {
      respuestaConcreta = "Sólo lectura de toda la info";
      riesgo = "Medio";
      comentario = "Se permite a usuarios externos leer toda la información de los calendarios secundarios. Esto expone descripciones de reuniones, participantes y ubicaciones de agendas compartidas o de proyectos de la organización.";
    } else if (extractedValue === "EXTERNAL_ALL_INFO_READ_WRITE") {
      respuestaConcreta = "Lectura y escritura de toda la info";
      riesgo = "Alto";
      comentario = "Se permite a usuarios externos ver y modificar eventos en los calendarios secundarios, lo que incrementa sustancialmente el riesgo de alteración o inyección de spam en agendas departamentales o compartidas.";
    } else if (extractedValue === "EXTERNAL_ALL_INFO_READ_WRITE_MANAGE") {
      respuestaConcreta = "Administración, lectura y escritura de toda la info";
      riesgo = "Alto";
      comentario = "Se otorga permiso total de administración y delegación a usuarios externos sobre los calendarios secundarios. Esto expone recursos y flujos de trabajo internos a total manipulación externa.";
    } else {
      respuestaConcreta = "Revisión manual";
      riesgo = "Medio";
      comentario = "La configuración no está explícitamente definida por la política, por lo que hereda el comportamiento predeterminado del sistema o requiere revisión manual en la consola administrativa (Calendar > General settings).";
    }

    Logger.log(`[LOG] Calendar Secondary External Sharing Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo} | Extracted: ${extractedValue}`);

    return {
      name: this.name,
      raw: rawData,
      valorPrincipal: respuestaConcreta,
      comentario120: comentario,
      riesgo120: riesgo,
      score120: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _buildErrorResponse(msg) {
    Logger.log(`[ID-120] ERROR: ${msg}`);
    return { 
      name: this.name, 
      valorPrincipal: "ERROR", 
      riesgo120: "Medio", 
      score120: 2, 
      comentario120: msg 
    };
  }
}