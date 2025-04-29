const { Model } = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  class TarifaConsultoria extends Model {
    static associate(models) {
      TarifaConsultoria.belongsTo(models.Administrador, {
        foreignKey: 'id_administrador',
        as: 'administrador'
      });
      TarifaConsultoria.hasMany(models.ComparacionTarifas, {
        foreignKey: 'id_tarifa_consultoria',
        as: 'comparaciones'
      });
    }
  }

  TarifaConsultoria.init({
    id_tarifa_consultoria: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    id_administrador: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: 'administrador',
        key: 'id_administrador'
      }
    },
    archivo: {
      type: DataTypes.TEXT,
      allowNull: false,
      validate: {
        notEmpty: true
      }
    },
    fecha_subida: {
      type: DataTypes.DATE,
      defaultValue: DataTypes.NOW
    }
  }, {
    sequelize,
    modelName: 'TarifaConsultoria',
    tableName: 'tarifa_consultoria',
    timestamps: false
  });

  return TarifaConsultoria;
};