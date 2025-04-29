const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class ComparacionTarifas extends Model {
    static associate(models) {
      ComparacionTarifas.belongsTo(models.Tarifa, {
        foreignKey: 'id_tarifa_usuario',
        as: 'tarifaUsuario'
      });
      ComparacionTarifas.belongsTo(models.TarifaConsultoria, {
        foreignKey: 'id_tarifa_consultoria',
        as: 'tarifaConsultoria'
      });
    }
  }

  ComparacionTarifas.init({
    id_comparacion: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    id_tarifa_usuario: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: 'tarifa',
        key: 'id_tarifa'
      }
    },
    id_tarifa_consultoria: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: 'tarifa_consultoria',
        key: 'id_tarifa_consultoria'
      }
    },
    resultado: {
      type: DataTypes.TEXT,
      allowNull: false,
      validate: {
        notEmpty: true
      }
    },
    fecha_comparacion: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW
    }
  }, {
    sequelize,
    modelName: 'ComparacionTarifas',
    tableName: 'comparacion_tarifas',
    timestamps: false
  });

  return ComparacionTarifas;
};